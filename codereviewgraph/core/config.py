"""Core configuration module for CodeReviewGraph."""
from pydantic import BaseModel, Field
import os


class Settings(BaseModel):
    """Application settings with environment variable defaults."""
    llm_provider: str = Field(default_factory=lambda: os.getenv("LLM_PROVIDER", "mock"))
    gemini_api_key: str = Field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    api_host: str = Field(default_factory=lambda: os.getenv("API_HOST", "127.0.0.1"))
    api_port: int = Field(default_factory=lambda: int(os.getenv("API_PORT", "8000")))
    max_tokens: int = 4096
    temperature: float = 0.0

    # Google OAuth 2.0 & Session Security Settings
    google_client_id: str = Field(default_factory=lambda: os.getenv("GOOGLE_CLIENT_ID", ""))
    google_client_secret: str = Field(default_factory=lambda: os.getenv("GOOGLE_CLIENT_SECRET", ""))
    google_callback_url: str = Field(default_factory=lambda: os.getenv("GOOGLE_CALLBACK_URL", ""))
    session_secret: str = Field(default_factory=lambda: os.getenv("SESSION_SECRET", ""))
    app_base_url: str = Field(default_factory=lambda: os.getenv("APP_BASE_URL", "http://localhost:8000"))
    database_path: str = Field(default_factory=lambda: os.getenv("DATABASE_PATH", ""))
    environment: str = Field(default_factory=lambda: os.getenv("ENVIRONMENT", os.getenv("NODE_ENV", "development")))


settings = Settings()
