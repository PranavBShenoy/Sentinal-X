"""
Authentication for the Runtime Broker.

The broker requires an X-Broker-Key header on every request, validated
against the shared BROKER_API_KEY. This authenticates the Celery worker
(or orchestrator) as an authorized broker client.

In development, BROKER_AUTH_REQUIRED may be disabled to allow local
testing without a configured key, but production must always require auth.
"""

from __future__ import annotations

import hmac
from fastapi import HTTPException, Request, status

from app.core.config import get_settings

settings = get_settings()


def require_broker_key(request: Request) -> None:
    """
    FastAPI dependency enforcing broker API key authentication.

    Rejects requests with a missing or invalid X-Broker-Key header.
    Production always requires auth; development may opt out via
    BROKER_AUTH_REQUIRED=False.
    """
    provided = request.headers.get("X-Broker-Key", "")
    _validate_broker_key(provided)


def validate_broker_key_header(provided: str) -> None:
    """Validate a raw X-Broker-Key header value; raises HTTPException on failure."""
    _validate_broker_key(provided)


def _validate_broker_key(provided: str) -> None:
    expected = settings.BROKER_API_KEY
    if not settings.BROKER_AUTH_REQUIRED:
        return
    if not expected:
        # Misconfigured: auth required but no key configured -> fail closed.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Broker authentication is not configured.",
        )
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing broker API key.",
        )
