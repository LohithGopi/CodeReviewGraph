"""API route handlers for CodeReviewGraph."""
import uuid
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from codereviewgraph.core.state import AuditReport
from codereviewgraph.graph.workflow import review_app
from codereviewgraph.storage.checkpointer import checkpoint_manager

router = APIRouter()


class AuditRequest(BaseModel):
    code: str = Field(description="Source code string to review")
    language: str = Field(default="python", description="Programming language")
    file_path: Optional[str] = Field(default=None, description="Optional path to target file")
    thread_id: Optional[str] = Field(default=None, description="Run/thread ID for checkpointing")


class AuditResponse(BaseModel):
    thread_id: str
    status: str
    report: Optional[AuditReport] = None
    stage: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


@router.get("/health", response_model=HealthResponse)
def health_check():
    """Health check endpoint for smoke tests and orchestrator gates."""
    return HealthResponse(
        status="healthy",
        service="codereviewgraph",
        version="0.1.0"
    )


@router.post("/api/audit", response_model=AuditResponse)
def audit_code(request: AuditRequest):
    """Execute the multi-agent code review workflow."""
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="Source code cannot be empty.")

    thread_id = request.thread_id or str(uuid.uuid4())
    config = {"configurable": {"thread_id": thread_id}}
    
    initial_state = {
        "raw_code": request.code,
        "language": request.language,
        "file_path": request.file_path,
        "current_stage": "STARTED"
    }

    try:
        final_state = review_app.invoke(initial_state, config=config)
        return {
            "thread_id": thread_id,
            "status": "SUCCESS",
            "report": final_state.get("final_report"),
            "stage": final_state.get("current_stage")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit workflow failed: {str(e)}")


@router.get("/api/runs/{thread_id}")
def get_run_checkpoint(thread_id: str):
    """Retrieve checkpointed state for an audit run."""
    state = checkpoint_manager.get_run_state(review_app, thread_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"No run found for thread_id '{thread_id}'")
    return state
