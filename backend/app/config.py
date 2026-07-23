"""Application configuration, sourced from environment variables / .env file."""

from functools import lru_cache
from typing import List, Union

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "VACE - Vulnerability Assessment Consolidation Engine"
    ENV: str = "development"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # CORS - comma-separated list of allowed origins in the environment
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    # Database (PostgreSQL)
    DATABASE_URL: str = "postgresql://vace_user:vace_password@localhost:5432/vace_db"

    # Redis (used for caching / task queue)
    REDIS_URL: str = "redis://localhost:6379/0"

    # Nessus API
    NESSUS_URL: str = ""
    NESSUS_ACCESS_KEY: str = ""
    NESSUS_SECRET_KEY: str = ""
    NESSUS_VERIFY_SSL: bool = True

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_cors_origins(cls, value: Union[str, List[str]]) -> List[str]:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor so the .env file is only parsed once."""
    return Settings()


settings = get_settings()
