"""FastAPI application factory for CodeReviewGraph."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from codereviewgraph.api.routes import router

app = FastAPI(
    title="CodeReviewGraph API",
    description="Stateful Multi-Agent Code Auditor & Refactoring Workflow powered by LangGraph & LangChain",
    version="0.1.0"
)

# Allow local CORS for dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
