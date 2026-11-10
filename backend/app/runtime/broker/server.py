"""
SENTINEL-X Runtime Broker entrypoint.

Run with:  uvicorn app.runtime.broker.server:app --host 0.0.0.0 --port 8001

In production this runs as a separate service holding the Docker socket.
The Celery worker mounts no socket and talks to this broker over HTTP.
"""

from __future__ import annotations

import uvicorn

from app.runtime.broker.app import app

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)  # noqa: S104 — broker must listen on all interfaces so the worker container can reach it via the compose service name; host port is mapped to 127.0.0.1 only in docker-compose.
