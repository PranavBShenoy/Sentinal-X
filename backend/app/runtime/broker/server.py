"""
SENTINEL-X Runtime Broker entrypoint.

Run with:  uvicorn app.runtime.broker.server:app --host 0.0.0.0 --port 8001

In production this runs as a separate service holding the Docker socket.
The Celery worker mounts no socket and talks to this broker over HTTP.
"""

from __future__ import annotations

import sys

import uvicorn

from app.core.config import get_settings
from app.runtime.broker.app import app

settings = get_settings()


def _validate_startup_config() -> None:
    """Fail fast if the broker is configured insecurely.

    In production, BROKER_API_KEY must be set and at least 32 characters.
    If BROKER_AUTH_REQUIRED is true but no key is configured, the broker
    must not start (fail closed).
    """
    if settings.BROKER_AUTH_REQUIRED and not settings.BROKER_API_KEY:
        print(
            "FATAL: BROKER_AUTH_REQUIRED=true but BROKER_API_KEY is not set. "
            "Generate one with: python3 -c 'import secrets; print(secrets.token_hex(32))'",
            file=sys.stderr,
        )
        sys.exit(1)

    if settings.APP_ENV == "production":
        if len(settings.BROKER_API_KEY) < 32:
            print(
                "FATAL: BROKER_API_KEY must be at least 32 characters in production.",
                file=sys.stderr,
            )
            sys.exit(1)


if __name__ == "__main__":
    _validate_startup_config()
    uvicorn.run(
        app,
        host="0.0.0.0",  # noqa: S104  # nosec B104 — container peers need the service address; Compose publishes this port on 127.0.0.1 only.
        port=8001,
        timeout_keep_alive=30,  # F-9: bounded keep-alive to slowloris
        limit_concurrency=50,   # F-9: bound concurrent connections
        timeout_graceful_shutdown=30,  # F-9: bounded shutdown drain
    )
