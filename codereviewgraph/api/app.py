"""FastAPI application factory for CodeReviewGraph."""
import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from codereviewgraph.api.routes import router

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(
    title="CodeReviewGraph API & Dashboard",
    description="Stateful Multi-Agent Code Auditor & Refactoring Workflow powered by LangGraph & LangChain",
    version="0.1.0"
)

# CORS configuration for local development and Vercel deployments
allowed_origin_regex = os.getenv(
    "ALLOWED_ORIGIN_REGEX",
    r"^https://[a-zA-Z0-9_-]+\.vercel\.app$"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:8000",
    ],
    allow_origin_regex=allowed_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/", include_in_schema=False)
def serve_dashboard():
    """Serve the interactive web frontend dashboard."""
    index_file = STATIC_DIR / "index.html"
    if index_file.is_file():
        return FileResponse(index_file)
    return {"message": "CodeReviewGraph API is running. Visit /docs for Swagger UI."}


if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
