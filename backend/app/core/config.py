"""
SENTINEL-X Backend Application Configuration.

All settings are sourced from environment variables.
Never hardcode secrets or environment-specific values here.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------ #
    # Application
    # ------------------------------------------------------------------ #
    APP_ENV: str = "development"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    APP_DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # ------------------------------------------------------------------ #
    # Database
    # ------------------------------------------------------------------ #
    DATABASE_URL: str = Field(
        default="postgresql+psycopg2://sentinelx:sentinelx_dev@localhost:5432/sentinelx",
        description="SQLAlchemy database URL",
    )
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20

    # ------------------------------------------------------------------ #
    # Redis / Celery
    # ------------------------------------------------------------------ #
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # ------------------------------------------------------------------ #
    # Security
    # ------------------------------------------------------------------ #
    JWT_SECRET: str = Field(
        default="INSECURE_DEVELOPMENT_SECRET_CHANGE_IN_PRODUCTION",
        description="JWT signing secret — must be changed in production",
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    ENCRYPTION_KEY: str = Field(
        default="",
        description="Fernet symmetric key for encrypting sensitive DB columns",
    )

    # ------------------------------------------------------------------ #
    # CORS
    # ------------------------------------------------------------------ #
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    # ------------------------------------------------------------------ #
    # GitHub
    # ------------------------------------------------------------------ #
    GITHUB_APP_ID: Optional[str] = None
    GITHUB_APP_PRIVATE_KEY_PATH: Optional[str] = None
    GITHUB_CLIENT_ID: Optional[str] = None
    GITHUB_CLIENT_SECRET: Optional[str] = None
    GITHUB_WEBHOOK_SECRET: Optional[str] = None
    GITHUB_CALLBACK_URL: str = "http://localhost:8000/api/v1/auth/github/callback"

    # ------------------------------------------------------------------ #
    # AI — OpenRouter
    # ------------------------------------------------------------------ #
    LLM_PROVIDER: str = "openrouter"
    OPENROUTER_API_KEY: Optional[str] = None
    OPENROUTER_MODEL: str = "anthropic/claude-3-haiku"
    OPENROUTER_SITE_URL: str = "http://localhost:5173"
    OPENROUTER_APP_NAME: str = "SENTINEL-X"
    OPENROUTER_MAX_TOKENS: int = 2000
    OPENROUTER_TIMEOUT_SECONDS: int = 60

    # ------------------------------------------------------------------ #
    # Scanner tool paths
    # ------------------------------------------------------------------ #
    SEMGREP_PATH: str = "/home/pranav/Sentinal-X/bin/semgrep" if os.path.exists("/home/pranav/Sentinal-X/bin/semgrep") else "semgrep"
    SEMGREP_RULES_PATH: str = "/home/pranav/Sentinal-X/rules/semgrep/default_rules.json"
    GITLEAKS_PATH: str = "/home/pranav/Sentinal-X/bin/gitleaks" if os.path.exists("/home/pranav/Sentinal-X/bin/gitleaks") else "gitleaks"
    SYFT_PATH: str = "/home/pranav/Sentinal-X/bin/syft" if os.path.exists("/home/pranav/Sentinal-X/bin/syft") else "syft"
    GRYPE_PATH: str = "/home/pranav/Sentinal-X/bin/grype" if os.path.exists("/home/pranav/Sentinal-X/bin/grype") else "grype"
    OSV_PATH: str = "/home/pranav/Sentinal-X/bin/osv-scanner" if os.path.exists("/home/pranav/Sentinal-X/bin/osv-scanner") else "osv-scanner"
    TRIVY_PATH: str = "/home/pranav/Sentinal-X/bin/trivy" if os.path.exists("/home/pranav/Sentinal-X/bin/trivy") else "trivy"
    ZAP_API_URL: str = "http://localhost:8080"

    # ------------------------------------------------------------------ #
    # Assessment workspaces
    # ------------------------------------------------------------------ #
    ASSESSMENT_WORKSPACE_BASE: str = "/tmp/sentinelx/workspaces"
    ASSESSMENT_WORKSPACE_MAX_AGE_HOURS: int = 24

    # ------------------------------------------------------------------ #
    # Worker / Performance
    # ------------------------------------------------------------------ #
    WORKER_CONCURRENCY: int = 2
    SCANNER_TIMEOUT_SECONDS: int = 300
    RUNTIME_PROVISIONING_TIMEOUT_SECONDS: int = 120
    DYNAMIC_TEST_TIMEOUT_SECONDS: int = 180

    # ------------------------------------------------------------------ #
    # Rate limiting
    # ------------------------------------------------------------------ #
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 60
    LOGIN_RATE_LIMIT_PER_MINUTE: int = 10

    @field_validator("JWT_SECRET")
    @classmethod
    def check_jwt_secret(cls, v: str) -> str:
        if v == "INSECURE_DEVELOPMENT_SECRET_CHANGE_IN_PRODUCTION":
            import warnings
            warnings.warn(
                "JWT_SECRET is set to the insecure default. Set a secure random value in production.",
                stacklevel=2,
            )
        if len(v) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters")
        return v


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
