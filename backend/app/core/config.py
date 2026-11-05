"""Application configuration loaded strictly from environment variables or .env file."""

from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration.

    Security rule: Secrets have NO insecure fallback defaults. Missing or invalid
    configuration will fail fast on startup.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    PROJECT_NAME: str = "CeylonGo Shared API"
    DEBUG: bool = False
    API_AUTH_PREFIX: str = "/api/auth"

    # JWT Configuration: Required from environment. No insecure hardcoded fallback.
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # CORS Configuration
    CORS_ORIGINS: List[str] = [
        "http://localhost:4200",
        "http://127.0.0.1:4200",
    ]

    # In-Memory Rate Limiting Configuration (Single-Process Sliding Window)
    RATE_LIMIT_LOGIN_MAX_ATTEMPTS: int = 5
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: int = 60
    RATE_LIMIT_MAX_TRACKED_IPS: int = 10000

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if not v or len(v.strip()) < 32:
            raise ValueError("SECRET_KEY must be a non-empty string of at least 32 characters.")
        return v.strip()

    @field_validator("ALGORITHM")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        allowed = {"HS256", "HS384", "HS512"}
        if v not in allowed:
            raise ValueError(f"Unsupported JWT signing algorithm: '{v}'. Must be one of {allowed}")
        return v

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            import json
            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                return [i.strip() for i in v.split(",") if i.strip()]
        return v


def get_settings() -> Settings:
    """Instantiate and return settings."""
    return Settings()


# Primary settings instance
settings = get_settings()
