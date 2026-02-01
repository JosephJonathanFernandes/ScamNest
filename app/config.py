"""
Configuration settings for the Honeypot API.
"""

from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    api_key: str = "your-secret-api-key"
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    guvi_callback_url: str = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    callback_timeout: int = 10
    min_messages_for_callback: int = 3
    scam_confidence_threshold: float = 0.7
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
