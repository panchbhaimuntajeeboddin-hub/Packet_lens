"""Application configuration settings."""

from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global configuration settings for PacketLens."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "PacketLens — Network Traffic Analyzer"
    VERSION: str = "0.1.0"
    DEBUG: bool = True

    # Database
    DATABASE_URL: str = "sqlite:///./packetlens.db"

    # File Upload Limits
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    TEMP_UPLOAD_DIR: Path = Path("backend/uploads")

    # Allowed CORS Origins (Vite + React dev server)
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Security & Session Authentication
    SECRET_KEY: str = "packetlens-cybersecurity-secret-key-32-chars-minimum-token-protection"
    JWT_ALGORITHM: str = "HS256"
    SESSION_EXPIRE_MINUTES: int = 60 * 12  # 12 hours
    SESSION_COOKIE_NAME: str = "packetlens_session"
    COOKIE_SECURE: bool = False  # Set to True when deploying behind HTTPS in production
    COOKIE_SAMESITE: str = "lax"  # Prevent CSRF on cross-site requests



settings = Settings()
