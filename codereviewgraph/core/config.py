"""Core configuration module for CodeReviewGraph."""
from __future__ import annotations

import os
from pathlib import Path
from pydantic import BaseModel, Field


def _load_env_file() -> None:
    """Load key-value pairs from .env file into os.environ if not already present."""
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent.parent / ".env",
    ]
    for env_path in candidates:
        if env_path.is_file():
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip("'\"")
                            if k and k not in os.environ:
                                os.environ[k] = v
                break
            except Exception:
                pass


_load_env_file()

DEFAULT_GOOGLE_CLIENT_ID = "985395568511-65nv6sl44qvkpcj7aac5ji33he8ms1jl.apps.googleusercontent.com"


class Settings(BaseModel):
    """Application settings with environment variable defaults."""
    llm_provider: str = Field(default_factory=lambda: os.getenv("LLM_PROVIDER", "mock"))
    gemini_api_key: str = Field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    api_host: str = Field(default_factory=lambda: os.getenv("API_HOST", "127.0.0.1"))
    api_port: int = Field(default_factory=lambda: int(os.getenv("API_PORT", "8000")))
    max_tokens: int = 4096
    temperature: float = 0.0

    # Google OAuth 2.0 & Session Security Settings
    google_client_id: str = Field(default_factory=lambda: os.getenv("GOOGLE_CLIENT_ID", DEFAULT_GOOGLE_CLIENT_ID))
    google_client_secret: str = Field(default_factory=lambda: os.getenv("GOOGLE_CLIENT_SECRET", ""))
    google_callback_url: str = Field(default_factory=lambda: os.getenv("GOOGLE_CALLBACK_URL", ""))
    app_base_url: str = Field(default_factory=lambda: os.getenv("APP_BASE_URL", "http://localhost:8000"))
    database_path: str = Field(default_factory=lambda: os.getenv("DATABASE_PATH", ""))
    environment: str = Field(default_factory=lambda: os.getenv("ENVIRONMENT", os.getenv("NODE_ENV", "development")))


settings = Settings()
