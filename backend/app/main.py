"""
SENTINEL-X FastAPI Application.

Lead API Control Plane for AI-Powered Security Assessment.
Handles projects, users, assessments, findings, remediation, and reporting.
Enforces strict tenant isolation, CORS allowlists, structured logging, and safe exception handling.
"""
from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.database import engine
from app.core.logging import configure_logging, get_logger
from app.core.rate_limiter import limiter

settings = get_settings()
logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Lifespan Management
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup and shutdown lifecycle handler."""
    # 1. Configure structured logging
    configure_logging(settings.LOG_LEVEL)
    logger.info("Starting SENTINEL-X Backend API", env=settings.APP_ENV, host=settings.APP_HOST, port=settings.APP_PORT)

    # 2. Ensure base workspace directories exist
    base_ws = Path(settings.ASSESSMENT_WORKSPACE_BASE)
    base_ws.mkdir(parents=True, exist_ok=True)
    reports_ws = base_ws / "reports"
    reports_ws.mkdir(parents=True, exist_ok=True)

    yield

    logger.info("Shutting down SENTINEL-X Backend API")


# ---------------------------------------------------------------------------
# Middlewares
# ---------------------------------------------------------------------------


class RequestTrackingMiddleware(BaseHTTPMiddleware):
    """Assigns unique X-Request-ID to each incoming request and logs timing."""

    async def dispatch(self, request: Request, call_next):
        req_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = req_id

        start_time = time.monotonic()
        response = await call_next(request)
        duration_ms = round((time.monotonic() - start_time) * 1000, 2)

        response.headers["X-Request-ID"] = req_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"

        # Do not log auth passwords or tokens
        path = request.url.path
        if "/health" not in path:
            logger.info(
                "HTTP request processed",
                method=request.method,
                path=path,
                status=response.status_code,
                duration_ms=duration_ms,
                request_id=req_id,
            )

        return response


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------

docs_enabled = settings.APP_ENV.lower() != "production"

app = FastAPI(
    title="SENTINEL-X API",
    description="AI-Powered Application & Software Supply-Chain Security Assessment Platform",
    version="0.1.0",
    docs_url="/docs" if docs_enabled else None,
    redoc_url="/redoc" if docs_enabled else None,
    openapi_url="/openapi.json" if docs_enabled else None,
    lifespan=lifespan,
)

# CORS Middleware (Strict: only allowed origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)

app.add_middleware(RequestTrackingMiddleware)


# ---------------------------------------------------------------------------
# Global Exception Handlers
# ---------------------------------------------------------------------------


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all exception handler to ensure internal server errors
    never leak database passwords, file paths, or raw stack traces to users.
    """
    req_id = getattr(request.state, "request_id", "unknown")
    logger.error("Unhandled server exception", error=str(exc), request_id=req_id, exc_info=True)

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred. The incident has been recorded.",
            "request_id": req_id,
        },
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health", tags=["system"])
def health_check():
    """Health check endpoint for container orchestrators and monitoring."""
    rl_status = limiter.get_status()
    overall_status = "healthy" if not rl_status.get("degraded") else "degraded"
    return {
        "status": overall_status,
        "service": "sentinelx-api",
        "environment": settings.APP_ENV,
        "rate_limiter": rl_status,
        "timestamp": time.time(),
    }


# Mount API v1 router
app.include_router(api_router, prefix="/api/v1")
