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


settings = Settings()
