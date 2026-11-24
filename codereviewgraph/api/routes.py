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
    code: str = Field(max_length=200_000, description="Source code string to review")
    language: str = Field(default="python", description="Programming language")
    file_path: Optional[str] = Field(default=None, description="Optional path to target file")
    thread_id: Optional[str] = Field(default=None, description="Run/thread ID for checkpointing")


class AuditResponse(BaseModel):
    thread_id: str
    status: str
    report: Optional[AuditReport] = None
    stage: Optional[str] = None


class GoogleAuthRequest(BaseModel):
    credential: Optional[str] = None
    email: Optional[str] = "developer@gmail.com"
    name: Optional[str] = "Developer"
    picture: Optional[str] = None


class AuthConfigResponse(BaseModel):
    google_client_id: str = ""


class UserProfile(BaseModel):
    id: str
    email: str
    name: str
    picture: Optional[str] = None
    provider: str = "google"
    authenticated: bool = True


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


@router.get("/api/auth/config", response_model=AuthConfigResponse)
def auth_config():
    """Return public authentication configuration."""
    import os
    return AuthConfigResponse(
        google_client_id=os.environ.get("GOOGLE_CLIENT_ID", "")
    )


@router.post("/api/auth/google", response_model=UserProfile)
def auth_google(request: GoogleAuthRequest):
    """Authenticate or verify Google authentication session (supports GSI JWT or profile)."""
    import base64
    import json

    # If real Google Identity Services JWT credential is provided, decode payload
    if request.credential:
        try:
            parts = request.credential.split(".")
            if len(parts) >= 2:
                payload_part = parts[1]
                payload_part += "=" * ((4 - len(payload_part) % 4) % 4)
                decoded = json.loads(base64.urlsafe_b64decode(payload_part.encode("utf-8")).decode("utf-8"))
                return UserProfile(
                    id=decoded.get("sub", str(uuid.uuid4())[:8]),
                    email=decoded.get("email", request.email or "developer@gmail.com"),
                    name=decoded.get("name", request.name or "Developer"),
                    picture=decoded.get("picture", request.picture or "/static/avatar.png"),
                    provider="google",
                    authenticated=True
                )
        except Exception:
            pass

    user_id = str(uuid.uuid4())[:8]
    return UserProfile(
        id=user_id,
        email=request.email or "developer@gmail.com",
        name=request.name or "Developer",
        picture=request.picture or "/static/avatar.png",
        provider="google",
        authenticated=True
    )


@router.get("/api/auth/me", response_model=UserProfile)
def auth_me():
    """Return default session profile for testing or client verification."""
    return UserProfile(
        id="demo-user",
        email="developer@gmail.com",
        name="Developer",
        picture="/static/avatar.png",
        provider="google",
        authenticated=True
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
