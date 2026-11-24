"""FastAPI application factory for CodeReviewGraph."""
import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
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


@app.get("/login", include_in_schema=False)
def serve_login():
    """Serve the dedicated login authentication page."""
    login_file = STATIC_DIR / "login.html"
    if login_file.is_file():
        return FileResponse(login_file)
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/playground", include_in_schema=False)
def serve_playground():
    """Serve the dedicated live code playground workstation."""
    playground_file = STATIC_DIR / "playground.html"
    if playground_file.is_file():
        return FileResponse(playground_file)
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/google280d8fb78c0e8560.html", include_in_schema=False)
@app.get("/google280d8fb78c0e8560.html/", include_in_schema=False)
def serve_google_verification():
    """Serve Google site verification file directly with 200 OK and zero redirects."""
    return Response(
        content="google-site-verification: google280d8fb78c0e8560.html",
        media_type="text/html",
        status_code=200
    )


@app.get("/google{token}.html", include_in_schema=False)
def serve_generic_google_verification(token: str):
    """Serve generic Google site verification token with 200 OK."""
    return Response(
        content=f"google-site-verification: google{token}.html",
        media_type="text/html",
        status_code=200
    )




@app.get("/api", include_in_schema=False)
def api_overview():
    """API overview endpoint for friendly status discovery."""
    return {
        "service": "codereviewgraph",
        "status": "healthy",
        "docs_url": "/docs",
        "health_url": "/health",
        "endpoints": {
            "audit": "POST /api/audit",
            "runs": "GET /api/runs/{thread_id}"
        }
    }


if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
