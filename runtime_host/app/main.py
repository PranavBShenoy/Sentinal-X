"""
Runtime Host FastAPI application.

Serves the job-oriented API over mTLS:
  GET    /v1/runtime/health          (unauthenticated liveness check)
  POST   /v1/runtime/jobs/submit     (mTLS + mutation token)
  GET    /v1/runtime/jobs/{id}/status (mTLS + read token)
  GET    /v1/runtime/jobs/{id}/logs   (mTLS + read token)
  POST   /v1/runtime/jobs/{id}/cancel (mTLS + mutation token)

Verifies mTLS client cert + asymmetric job capability tokens on every
protected request. Never touches control-plane databases or secrets.

Health checks reveal no secrets or sensitive job information.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status

from .auth import (
    AuthContext,
    Authenticator,
)
from .config import (
    load_config,
    load_proxy_token,
    validate_client_ca_pem,
    validate_public_key_pem,
)
from .executor import DockerExecutor
from .jobs import JobStore
from .nonce_store import NonceStore
from .policy import ALLOWED_OPERATIONS, DEFAULT_POLICY
from .reconciliation import reconcile_orphaned_jobs
from .schemas import (
    HealthResponse,
    JobCancelResponse,
    JobLogsResponse,
    JobStatusResponse,
    JobSubmitRequest,
    JobSubmitResponse,
)

logger = logging.getLogger(__name__)

# Global instances (set in create_app)
_authenticator: Authenticator | None = None
_job_store: JobStore | None = None
_nonce_store: NonceStore | None = None
_executor: DockerExecutor | None = None
_public_key_pem: bytes | None = None
_proxy_token: str | None = None
_client_ca_pem: bytes | None = None
_expected_audience: str | None = None
_expected_issuer: str = "sentinelx-authorization"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize components on startup.

    Production requires a valid public verification key. Without it,
    the service cannot authenticate any request and must not start.
    """
    global _authenticator, _job_store, _nonce_store, _executor

    # Job store and nonce store are always required
    _job_store = JobStore()
    _nonce_store = NonceStore()

    # Executor is required for Docker operations
    _executor = DockerExecutor(policy=DEFAULT_POLICY)

    # Authenticator is REQUIRED — fail startup without a public key or client CA
    if not _public_key_pem:
        logger.critical(
            "Runtime Host cannot start: public verification key is required "
            "but was not provided. Set RUNTIME_HOST_PUBLIC_KEY_PATH."
        )
        raise RuntimeError(
            "public verification key is required to start Runtime Host"
        )
    if not _client_ca_pem:
        logger.critical(
            "Runtime Host cannot start: trusted client CA is required but was "
            "not provided. Set RUNTIME_HOST_CLIENT_CA_PATH."
        )
        raise RuntimeError(
            "trusted client CA is required to start Runtime Host"
        )

    _authenticator = Authenticator(
        public_key_pem=_public_key_pem,
        expected_audience=_expected_audience,
        expected_issuer=_expected_issuer,
        require_mtls=True,
        proxy_token=_proxy_token,
        client_ca_pem=_client_ca_pem,
    )

    # Reconcile only after required authentication material validates and
    # before accepting work; names derive from persisted job records.
    reconcile_orphaned_jobs(_job_store, _executor)

    logger.info("Runtime Host service started with authentication enabled")
    yield
    logger.info("Runtime Host service shutting down")


async def get_auth(request: Request) -> AuthContext:
    """FastAPI dependency: authenticate the request via mTLS + JWT.

    Requires the global authenticator to be configured (set in lifespan).
    Raises HTTPException if authentication is not configured or fails.
    """
    if _authenticator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication not configured",
        )
    return await _authenticator.authenticate(request)


def create_app(
    public_key_pem: bytes | None = None,
    expected_audience: str | None = None,
    expected_issuer: str | None = None,
    job_store_db_path: str = "/var/lib/runtime_host/jobs.db",
    nonce_store_db_path: str = "/var/lib/runtime_host/nonces.db",
    proxy_token: str | None = None,
    client_ca_pem: bytes | None = None,
) -> FastAPI:
    """Create the FastAPI application.

    When ``public_key_pem``, ``proxy_token``, or ``client_ca_pem`` is omitted,
    configuration is loaded from the environment and validated fail-closed.
    This is the path used by ``uvicorn --factory app.main:create_app``.

    Args:
        public_key_pem: Ed25519 public verification key (PEM bytes).
        expected_audience: Expected aud claim value for tokens.
        expected_issuer: Expected iss claim value for tokens.
        job_store_db_path: Path to the SQLite job store database.
        nonce_store_db_path: Path to the SQLite nonce store database.
        proxy_token: Shared token injected by the trusted Nginx proxy.
        client_ca_pem: Trusted client CA certificate(s) for chain verification.
    """
    global _public_key_pem, _proxy_token, _client_ca_pem
    global _expected_audience, _expected_issuer

    config = None
    if (
        public_key_pem is None
        or proxy_token is None
        or client_ca_pem is None
    ):
        config = load_config()

    if public_key_pem is None:
        public_key_pem = config.public_key_pem
    if proxy_token is None:
        proxy_token = config.proxy_token
    if client_ca_pem is None:
        client_ca_pem = config.client_ca_pem
    if expected_audience is None and config is not None:
        expected_audience = config.expected_audience
    if expected_issuer is None:
        expected_issuer = (
            config.expected_issuer if config is not None else "sentinelx-authorization"
        )

    validate_public_key_pem(public_key_pem)
    load_proxy_token(proxy_token)
    validate_client_ca_pem(client_ca_pem)

    _public_key_pem = public_key_pem
    _proxy_token = proxy_token
    _client_ca_pem = client_ca_pem
    _expected_audience = expected_audience
    _expected_issuer = expected_issuer

    app = FastAPI(
        title="SENTINEL-X Runtime Host",
        description="Separate Runtime Execution Plane service",
        version="1.0.0",
        lifespan=lifespan,
    )

    # ------------------------------------------------------------------
    # Middleware: log requests without tokens/secrets
    # ------------------------------------------------------------------
    @app.middleware("http")
    async def request_logging_middleware(request: Request, call_next):
        start = time.time()
        # Log method and path only — never token, URL, or headers
        logger.info(
            "Request",
            extra={
                "method": request.method,
                "path": request.url.path,
            },
        )
        response = await call_next(request)
        duration = (time.time() - start) * 1000
        logger.info(
            "Response",
            extra={
                "status_code": response.status_code,
                "duration_ms": round(duration, 2),
            },
        )
        return response

    # ------------------------------------------------------------------
    # Endpoints — unauthenticated health check only
    # ------------------------------------------------------------------

    @app.get("/v1/runtime/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        """Liveness and Docker availability check.

        Unauthenticated by design: returns only status and docker_available.
        No secrets, tokens, or job information are exposed.
        """
        docker_available = _executor.health_check() if _executor else False
        return HealthResponse(
            status="healthy" if docker_available else "degraded",
            docker_available=docker_available,
        )

    # ------------------------------------------------------------------
    # Endpoints — authenticated (mTLS + JWT capability token)
    # ------------------------------------------------------------------

    @app.post("/v1/runtime/jobs/submit", response_model=JobSubmitResponse)
    async def submit_job(
        request: Request,
        job_request: JobSubmitRequest,
        auth: AuthContext = Depends(get_auth),  # noqa: B008
    ) -> JobSubmitResponse:
        """Submit a job to the Runtime Execution Plane.

        Requires mTLS + mutation job capability token.
        Validates the request, checks idempotency, and dispatches to the
        Docker executor.
        """
        # Submit requires a mutation token
        if auth.token_type != "mutation":  # nosec B105
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Mutation token required for job submission",
            )

        # Verify token's tenant/assessment match the request
        if auth.tenant_id != job_request.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tenant mismatch between token and request",
            )
        if auth.assessment_id != job_request.assessment_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Assessment mismatch between token and request",
            )

        # Verify token's operation matches request operation
        if auth.operation != job_request.operation:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation mismatch between token and request",
            )

        # Verify token's job_id matches request job_id
        if auth.job_id != job_request.job_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Job ID mismatch between token and request",
            )

        # Verify token's resources cover requested resources
        for resource in job_request.resources:
            if resource not in auth.resources:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Resource not authorized: {resource}",
                )

        # Validate idempotency
        existing = _job_store.get_job_by_idempotency_key(job_request.idempotency_key)
        if existing:
            return JobSubmitResponse(
                job_id=existing["job_id"],
                status=existing["status"],
                message="Duplicate submission; returning existing job",
                target_url=existing.get("target_url"),
            )

        # Create job in store
        created = _job_store.create_job(
            job_id=job_request.job_id,
            idempotency_key=job_request.idempotency_key,
            tenant_id=job_request.tenant_id,
            assessment_id=job_request.assessment_id,
            operation=job_request.operation,
            resources=job_request.resources,
            resource_limits=job_request.resource_limits,
        )
        if not created:
            # Race condition: job was created between check and insert
            existing = _job_store.get_job(job_request.job_id)
            if existing:
                return JobSubmitResponse(
                    job_id=existing["job_id"],
                    status=existing["status"],
                    message="Duplicate submission; returning existing job",
                    target_url=existing.get("target_url"),
                )
            return JobSubmitResponse(
                job_id=job_request.job_id,
                status="FAILED",
                message="Failed to create job",
            )

        # Dispatch based on operation
        operation = job_request.operation
        if operation not in ALLOWED_OPERATIONS:
            _job_store.update_status(
                job_id=job_request.job_id,
                status="FAILED",
                error=f"Invalid operation: {operation}",
            )
            return JobSubmitResponse(
                job_id=job_request.job_id,
                status="FAILED",
                message=f"Invalid operation: {operation}",
            )

        if operation == "build":
            claimed_sha256 = auth.resource_limits.get("artifact_sha256")
            if (
                not job_request.artifact_url
                or not isinstance(claimed_sha256, str)
                or not claimed_sha256
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Build requires an artifact URL and token-claimed SHA-256",
                )
            if (
                job_request.artifact_sha256 is not None
                and job_request.artifact_sha256.lower() != claimed_sha256.lower()
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Artifact hash does not match the capability claim",
                )

            result = _executor.submit_build(
                job_id=job_request.job_id,
                assessment_id=job_request.assessment_id,
                artifact_url=job_request.artifact_url,
                artifact_sha256=claimed_sha256,
                image_tag=job_request.image_tag
                or f"sentinelx-app-{job_request.assessment_id[:12]}",
                network_mode=job_request.resource_limits.get(
                    "network_mode", "none"
                ),
            )
            _job_store.update_status(
                job_id=job_request.job_id,
                status=result.status,
                error=result.message if result.status == "FAILED" else None,
            )
            return result

        elif operation == "run":
            import socket

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((_executor.bind_ip, 0))
                host_port = s.getsockname()[1]

            result = _executor.submit_run(
                job_id=job_request.job_id,
                assessment_id=job_request.assessment_id,
                image_tag=job_request.image_tag
                or f"sentinelx-app-{job_request.assessment_id[:12]}",
                container_name=job_request.container_name
                or f"sentinelx-cont-{job_request.assessment_id[:12]}",
                network_name=job_request.network_name
                or f"sentinelx-net-{job_request.assessment_id[:12]}",
                app_port=job_request.app_port or 8000,
                host_port=host_port,
            )
            _job_store.update_status(
                job_id=job_request.job_id,
                status=result.status,
                target_url=result.target_url,
                error=result.message if result.status == "FAILED" else None,
            )
            return result

        elif operation == "cleanup":
            result = _executor.submit_cleanup(
                job_id=job_request.job_id,
                container_name=job_request.container_name
                or f"sentinelx-cont-{job_request.assessment_id[:12]}",
                network_name=job_request.network_name
                or f"sentinelx-net-{job_request.assessment_id[:12]}",
                image_tag=job_request.image_tag
                or f"sentinelx-app-{job_request.assessment_id[:12]}",
            )
            _job_store.update_status(
                job_id=job_request.job_id,
                status=result.status,
            )
            return JobSubmitResponse(
                job_id=result.job_id,
                status=result.status,
                message=result.message,
            )

        elif operation == "cancel":
            result = _executor.cancel(
                job_id=job_request.job_id,
                container_name=job_request.container_name
                or f"sentinelx-cont-{job_request.assessment_id[:12]}",
            )
            _job_store.update_status(
                job_id=job_request.job_id,
                status=result.status,
            )
            return JobSubmitResponse(
                job_id=result.job_id,
                status=result.status,
                message=result.message,
            )

        return JobSubmitResponse(
            job_id=job_request.job_id,
            status="FAILED",
            message=f"Unhandled operation: {operation}",
        )

    @app.get("/v1/runtime/jobs/{job_id}/status", response_model=JobStatusResponse)
    async def get_job_status(
        job_id: str,
        auth: AuthContext = Depends(get_auth),  # noqa: B008
    ) -> JobStatusResponse:
        """Get the status of a submitted job.

        Requires mTLS + read token.
        """
        # Read endpoints permit read tokens only
        if auth.token_type != "read":  # nosec B105
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Read token required for job status",
            )

        # Verify the requested job belongs to the token's assessment/tenant
        job = _job_store.get_job(job_id) if _job_store else None
        if not job:
            return JobStatusResponse(
                job_id=job_id,
                status="FAILED",
                error="Job not found",
            )

        if auth.tenant_id != job["tenant_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tenant mismatch: job belongs to another tenant",
            )
        if auth.assessment_id != job["assessment_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Assessment mismatch: job belongs to another assessment",
            )

        # For running jobs, check Docker status
        if job["status"] == "RUNNING":
            container_name = f"sentinelx-cont-{job['assessment_id'][:12]}"
            docker_status = _executor.get_status(
                job_id=job_id, container_name=container_name
            ) if _executor else None
            if docker_status:
                return docker_status

        return JobStatusResponse(
            job_id=job["job_id"],
            status=job["status"],
            target_url=job.get("target_url"),
            error=job.get("error"),
            created_at=job.get("created_at"),
            completed_at=job.get("completed_at"),
        )

    @app.get("/v1/runtime/jobs/{job_id}/logs", response_model=JobLogsResponse)
    async def get_job_logs(
        job_id: str,
        auth: AuthContext = Depends(get_auth),  # noqa: B008
    ) -> JobLogsResponse:
        """Get redacted container logs for a job.

        Requires mTLS + read token.
        """
        if auth.token_type != "read":  # nosec B105
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Read token required for job logs",
            )

        job = _job_store.get_job(job_id) if _job_store else None
        if not job:
            return JobLogsResponse(
                job_id=job_id,
                logs="Job not found",
            )

        if auth.tenant_id != job["tenant_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tenant mismatch: job belongs to another tenant",
            )
        if auth.assessment_id != job["assessment_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Assessment mismatch: job belongs to another assessment",
            )

        container_name = f"sentinelx-cont-{job['assessment_id'][:12]}"
        return _executor.get_logs(
            job_id=job_id, container_name=container_name
        ) if _executor else JobLogsResponse(
            job_id=job_id,
            logs="Executor not available",
        )

    @app.post("/v1/runtime/jobs/{job_id}/cancel", response_model=JobCancelResponse)
    async def cancel_job(
        job_id: str,
        auth: AuthContext = Depends(get_auth),  # noqa: B008
    ) -> JobCancelResponse:
        """Cancel/cleanup a job.

        Requires mTLS + mutation token.
        """
        if auth.token_type != "mutation":  # nosec B105
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Mutation token required for job cancellation",
            )

        job = _job_store.get_job(job_id) if _job_store else None
        if not job:
            return JobCancelResponse(
                job_id=job_id,
                status="FAILED",
                message="Job not found",
            )

        if auth.tenant_id != job["tenant_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tenant mismatch: job belongs to another tenant",
            )
        if auth.assessment_id != job["assessment_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Assessment mismatch: job belongs to another assessment",
            )

        container_name = f"sentinelx-cont-{job['assessment_id'][:12]}"
        result = _executor.cancel(
            job_id=job_id, container_name=container_name
        ) if _executor else JobCancelResponse(
            job_id=job_id,
            status="FAILED",
            message="Executor not available",
        )

        _job_store.update_status(job_id=job_id, status=result.status)
        return result

    return app
