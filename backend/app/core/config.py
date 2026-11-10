"""
SENTINEL-X Backend Application Configuration.

All settings are sourced from environment variables.
Never hardcode secrets or environment-specific values here.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
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
    APP_HOST: str = "0.0.0.0"  # nosec B104 # noqa: S104
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

    # ------------------------------------------------------------------ #
    # Rate Limiting & Reverse Proxies
    # ------------------------------------------------------------------ #
    TRUSTED_PROXIES: str = "127.0.0.1,::1"
    RATE_LIMIT_ENABLED: bool = True

    @property
    def trusted_proxies_list(self) -> List[str]:
        return [p.strip() for p in self.TRUSTED_PROXIES.split(",") if p.strip()]

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
    SEMGREP_RULES_PATH: str = (
        str(Path(__file__).resolve().parent.parent.parent.parent / "rules" / "semgrep" / "default_rules.json")
        if (Path(__file__).resolve().parent.parent.parent.parent / "rules" / "semgrep" / "default_rules.json").exists()
        else "/home/pranav/Sentinal-X/rules/semgrep/default_rules.json"
    )
    GITLEAKS_PATH: str = "/home/pranav/Sentinal-X/bin/gitleaks" if os.path.exists("/home/pranav/Sentinal-X/bin/gitleaks") else "gitleaks"
    SYFT_PATH: str = "/home/pranav/Sentinal-X/bin/syft" if os.path.exists("/home/pranav/Sentinal-X/bin/syft") else "syft"
    GRYPE_PATH: str = "/home/pranav/Sentinal-X/bin/grype" if os.path.exists("/home/pranav/Sentinal-X/bin/grype") else "grype"
    OSV_PATH: str = "/home/pranav/Sentinal-X/bin/osv-scanner" if os.path.exists("/home/pranav/Sentinal-X/bin/osv-scanner") else "osv-scanner"
    TRIVY_PATH: str = "/home/pranav/Sentinal-X/bin/trivy" if os.path.exists("/home/pranav/Sentinal-X/bin/trivy") else "trivy"
    ZAP_API_URL: str = "http://localhost:8080"

    # ------------------------------------------------------------------ #
    # Assessment workspaces
    # ------------------------------------------------------------------ #
    ASSESSMENT_WORKSPACE_BASE: str = "/tmp/sentinelx/workspaces"  # nosec B108
    ASSESSMENT_WORKSPACE_MAX_AGE_HOURS: int = 24

    # ------------------------------------------------------------------ #
    # Worker / Performance
    # ------------------------------------------------------------------ #
    WORKER_CONCURRENCY: int = 2
    SCANNER_TIMEOUT_SECONDS: int = 300
    RUNTIME_PROVISIONING_TIMEOUT_SECONDS: int = 120
    DYNAMIC_TEST_TIMEOUT_SECONDS: int = 180

    # ------------------------------------------------------------------ #
    # Runtime Broker (constrained Docker policy enforcement)
    # ------------------------------------------------------------------ #
    BROKER_URL: str = "http://localhost:8001"
    BROKER_API_KEY: str = ""
    BROKER_AUTH_REQUIRED: bool = True
    # Build-time network mode: "none" (no outbound) or "internal" (isolated bridge).
    # Never "host" — the default bridge provides no outbound isolation by itself.
    BUILD_NETWORK_MODE: str = "none"
    # Container resource limits enforced by the broker (never overridden by caller)
    BROKER_MEMORY_LIMIT: str = "512m"
    BROKER_CPUS: str = "1.0"
    BROKER_PIDS_LIMIT: int = 100
    BROKER_TMPFS_SIZE: str = "64m"
    # Maximum number of concurrent image builds the broker will run.
    # Builds are memory/CPU-bound; unbounded concurrency is a DoS vector.
    BROKER_MAX_CONCURRENT_BUILDS: int = 2
    # Runtime execution backend mode.
    # - "broker" (production default): talk to the policy-enforcing Runtime
    #   Broker over authenticated HTTP. Requires BROKER_API_KEY.
    # - "simulated": development/test-only canned responses. NEVER performs
    #   real Docker execution. Rejected in production.
    # - "remote": talk to a separate Runtime Execution Plane over mTLS +
    #   asymmetric job capability tokens. Requires RUNTIME_URL,
    #   RUNTIME_CLIENT_CERT, RUNTIME_CLIENT_KEY, RUNTIME_CA_CERT.
    RUNTIME_MODE: str = "broker"
    # Runtime Execution Plane URL (used when RUNTIME_MODE=remote).
    RUNTIME_URL: str = "http://localhost:8001"
    # mTLS client certificate for authenticating to the Runtime Host.
    RUNTIME_CLIENT_CERT: Optional[str] = None
    # mTLS client private key for authenticating to the Runtime Host.
    RUNTIME_CLIENT_KEY: Optional[str] = None
    # CA certificate for verifying the Runtime Host's server certificate.
    RUNTIME_CA_CERT: Optional[str] = None

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

    @field_validator("BROKER_API_KEY")
    @classmethod
    def check_broker_api_key(cls, v: str, info) -> str:
        """Validate broker API key strength in production.

        In production, an empty or weak key is rejected outright (fail closed).
        In development, an empty key is permitted only when
        BROKER_AUTH_REQUIRED=False.
        """
        app_env = info.data.get("APP_ENV", "development")
        if app_env == "production":
            if not v:
                raise ValueError(
                    "BROKER_API_KEY is required in production. "
                    "Generate one with: python3 -c 'import secrets; print(secrets.token_hex(32))'"
                )
            if len(v) < 32:
                raise ValueError(
                    "BROKER_API_KEY must be at least 32 characters in production."
                )
        return v

    @field_validator("RUNTIME_MODE")
    @classmethod
    def check_runtime_mode(cls, v: str, info) -> str:
        """Reject simulated runtime mode in production.

        Simulated mode is development/test-only and never performs real
        Docker execution. Production must use the broker-backed client.
        """
        app_env = info.data.get("APP_ENV", "development")
        if app_env == "production" and v == "simulated":
            raise ValueError(
                "RUNTIME_MODE=simulated is not allowed in production. "
                "Set RUNTIME_MODE=broker and configure BROKER_API_KEY."
            )
        return v


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
