"""Manual, live Stage 3B execution verification.

This test requires the local PostgreSQL database, a live Runtime Host behind
the mTLS proxy, real client certificates, matching Ed25519 keys, an allowlisted
immutable HTTPS tarball, and a working Runtime Host Docker daemon. It deliberately
uses no mocks, TestClient, monkeypatches, or simulated runtime clients.

The current RuntimeOrchestrator exposes a legacy synchronous lifecycle while
the Runtime Host API is job-oriented. This harness selects the real remote
client through RuntimeOrchestrator and sends the exact capability-bound job
requests through that client's real mTLS transport. It avoids fabricating a
job ID that would not match the signed capability token.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.authz.component import AuthorizationComponent
from app.core import database
from app.models import (
    Assessment,
    AuthorizationRequest,
    Project,
    RuntimeEnvironment,
    User,
    Worker,
)
from app.runtime.docker.orchestrator import RuntimeOrchestrator
from app.runtime.runtime_host_client import RemoteRuntimeClient


def _required_path(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        pytest.fail(f"{name} must be set to run the live execution test")
    path = Path(value).expanduser()
    if not path.is_file() or not os.access(path, os.R_OK):
        pytest.fail(f"{name} is missing or unreadable: {path}")
    return path


def _required_value(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.fail(f"{name} must be set to run the live execution test")
    return value


@pytest.fixture(scope="module")
def live_postgres():
    """Replace the unit-test SQLite engine with the explicitly selected local PG."""
    database_url = _required_value("STAGE_3B_DATABASE_URL")
    parsed = urlsplit(database_url.replace("postgresql+psycopg2://", "postgresql://", 1))
    if parsed.scheme != "postgresql" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        pytest.fail("STAGE_3B_DATABASE_URL must point to PostgreSQL on this host")

    original_engine = database.engine
    original_session_local = database.SessionLocal
    engine = create_engine(database_url, pool_pre_ping=True, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as connection:
            assert connection.exec_driver_sql("SELECT 1").scalar_one() == 1
        database.engine = engine
        database.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
            bind=engine,
        )
        yield engine
    finally:
        database.SessionLocal = original_session_local
        database.engine = original_engine
        engine.dispose()


@pytest.fixture
def live_identity(live_postgres):
    """Create short-lived DB-backed ownership, worker, and authorization rows."""
    cert_path = _required_path("RUNTIME_CLIENT_CERT")
    client_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    cert_fingerprint = hashlib.sha256(
        client_cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    username_suffix = uuid.uuid4().hex
    session = database.SessionLocal()
    user = User(
        email=f"stage3b-{username_suffix}@example.invalid",
        username=f"stage3b-{username_suffix[:20]}",
        is_active=True,
        is_verified=True,
    )
    session.add(user)
    session.flush()
    project = Project(owner_id=user.id, name=f"Stage 3B {username_suffix}")
    session.add(project)
    session.flush()
    assessment = Assessment(
        project_id=project.id,
        created_by_id=user.id,
        branch="stage-3b-live-test",
    )
    session.add(assessment)
    session.flush()
    worker = Worker(
        user_id=user.id,
        cert_fingerprint=cert_fingerprint,
        cert_subject=client_cert.subject.rfc4514_string(),
        is_active=True,
        is_revoked=False,
    )
    session.add(worker)
    request_id = f"stage3b-{uuid.uuid4()}"
    authorization_request = AuthorizationRequest(
        user_id=user.id,
        assessment_id=assessment.id,
        tenant_id=user.id,
        operation="provision",
        request_id=request_id,
        status="consumed",
        consumed_at=datetime.now(timezone.utc),
    )
    session.add(authorization_request)
    session.commit()

    identity = {
        "assessment_id": str(assessment.id),
        "request_id": request_id,
        "tenant_id": str(user.id),
        "worker_subject": client_cert.subject.rfc4514_string(),
    }
    try:
        yield identity
    finally:
        session.query(AuthorizationRequest).filter_by(request_id=request_id).delete()
        session.query(RuntimeEnvironment).filter_by(
            assessment_id=assessment.id
        ).delete()
        session.query(Worker).filter_by(user_id=user.id).delete()
        session.query(Assessment).filter_by(id=assessment.id).delete()
        session.query(Project).filter_by(id=project.id).delete()
        session.query(User).filter_by(id=user.id).delete()
        session.commit()
        session.close()


def _validate_artifact() -> tuple[str, str]:
    url = _required_value("STAGE_3B_ARTIFACT_URL")
    digest = _required_value("STAGE_3B_ARTIFACT_SHA256").lower()
    parsed = urlsplit(url)
    allowed_origins = {
        host.strip().lower()
        for host in os.environ.get("RUNTIME_ARTIFACT_ORIGINS", "").split(",")
        if host.strip()
    }
    if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
        pytest.fail("Artifact must be an immutable HTTPS URL without query or fragment")
    if parsed.hostname.lower() not in allowed_origins:
        pytest.fail("Artifact URL host must exactly match RUNTIME_ARTIFACT_ORIGINS")
    if parsed.hostname.lower() == "raw.githubusercontent.com":
        if not re.search(r"/[0-9a-f]{40}/.+\.tar\.gz$", parsed.path, re.IGNORECASE):
            pytest.fail("GitHub artifact URL must pin a 40-character commit and end in .tar.gz")
    elif not parsed.path.endswith(".tar.gz"):
        pytest.fail("Stage 3B artifact must be a .tar.gz archive")
    if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", digest):
        pytest.fail("STAGE_3B_ARTIFACT_SHA256 must contain a SHA-256 hex digest")
    return url, digest


def _dispatch(orchestrator: RuntimeOrchestrator, token: str, body: dict) -> dict:
    """Send one real job request through the orchestrator-selected mTLS client."""
    runtime = orchestrator.broker
    assert isinstance(runtime, RemoteRuntimeClient)
    runtime.job_token = token
    ok, response = runtime._request(
        "POST", "/v1/runtime/jobs/submit", json_body=body
    )
    assert ok, f"Runtime Host job submission failed: {response.get('error', response)}"
    return response


def test_live_remote_execution_build_run_logs_and_cleanup(live_identity):
    runtime_url = os.environ.get("RUNTIME_URL", "https://127.0.0.1:8443").rstrip("/")
    assert runtime_url == "https://127.0.0.1:8443", "Stage 3B must use the local mTLS proxy"
    artifact_url, artifact_sha256 = _validate_artifact()

    private_key_path = _required_path("STAGE_3B_AUTH_PRIVATE_KEY_PATH")
    public_key_path = _required_path("STAGE_3B_AUTH_PUBLIC_KEY_PATH")
    host_public_key_path = _required_path("STAGE_3B_RUNTIME_HOST_PUBLIC_KEY_PATH")
    private_key_pem = private_key_path.read_bytes()
    public_key_pem = public_key_path.read_bytes()
    host_public_key_pem = host_public_key_path.read_bytes()
    public_key = serialization.load_pem_public_key(public_key_pem)
    host_public_key = serialization.load_pem_public_key(host_public_key_pem)
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    host_public_der = host_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert public_der == host_public_der, "Signer public key must match Runtime Host verifier key"

    audience = os.environ.get("RUNTIME_HOST_AUDIENCE", "runtime-host")
    authorization = AuthorizationComponent(
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
    )
    runtime_client = RemoteRuntimeClient(
        runtime_url=runtime_url,
        client_cert=str(_required_path("RUNTIME_CLIENT_CERT")),
        client_key=str(_required_path("RUNTIME_CLIENT_KEY")),
        ca_cert=str(_required_path("RUNTIME_CA_CERT")),
        timeout_seconds=15.0,
        require_mtls=True,
    )
    orchestrator = RuntimeOrchestrator(runtime_client=runtime_client)
    assert isinstance(orchestrator.broker, RemoteRuntimeClient)
    assert orchestrator.is_docker_available(), "Runtime Host health check reports Docker unavailable"

    assessment_id = live_identity["assessment_id"]
    tenant_id = live_identity["tenant_id"]
    request_id = live_identity["request_id"]
    short_id = assessment_id[:12]
    resources = [
        f"sentinelx-cont-{short_id}",
        f"sentinelx-app-{short_id}",
        f"sentinelx-net-{short_id}",
    ]
    build_job_id = str(uuid.uuid4())
    run_job_id = str(uuid.uuid4())
    cleanup_job_id = str(uuid.uuid4())

    # Confirm the orchestrator's provenance request was committed and consumed.
    with database.db_session() as session:
        record = session.query(AuthorizationRequest).filter_by(request_id=request_id).one()
        assert record.status == "consumed"
        assert str(record.assessment_id) == assessment_id

    try:
        build_token = authorization.issue_mutation_token(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            operation="build",
            worker_cert_subject=live_identity["worker_subject"],
            resource_limits={"artifact_sha256": artifact_sha256},
            audience=audience,
            job_id=build_job_id,
        )
        build = _dispatch(
            orchestrator,
            build_token,
            {
                "idempotency_key": f"{request_id}:build",
                "job_id": build_job_id,
                "tenant_id": tenant_id,
                "assessment_id": assessment_id,
                "operation": "build",
                "resources": resources,
                "resource_limits": {"artifact_sha256": artifact_sha256},
                "artifact_url": artifact_url,
                "artifact_sha256": artifact_sha256,
                "image_tag": f"sentinelx-app-{short_id}",
            },
        )
        assert build.get("status") == "BUILDING", f"Build did not complete: {build}"

        run_token = authorization.issue_mutation_token(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            operation="run",
            worker_cert_subject=live_identity["worker_subject"],
            audience=audience,
            job_id=run_job_id,
        )
        run_response = _dispatch(
            orchestrator,
            run_token,
            {
                "idempotency_key": f"{request_id}:run",
                "job_id": run_job_id,
                "tenant_id": tenant_id,
                "assessment_id": assessment_id,
                "operation": "run",
                "resources": resources,
                "resource_limits": {},
                "image_tag": f"sentinelx-app-{short_id}",
                "container_name": f"sentinelx-cont-{short_id}",
                "network_name": f"sentinelx-net-{short_id}",
                "app_port": 8000,
            },
        )

        read_token = authorization.issue_read_token(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            operation="status",
            worker_cert_subject=live_identity["worker_subject"],
            audience=audience,
            job_id=run_job_id,
        )
        runtime_client.job_token = read_token
        deadline = time.monotonic() + 180
        final_status = ""
        target_url = run_response.get("target_url")
        while time.monotonic() < deadline:
            ok, final_status, status_target_url = runtime_client.get_job_status(run_job_id)
            assert ok, f"Runtime Host status request failed: {final_status}"
            target_url = status_target_url or target_url
            if final_status in {"RUNNING", "COMPLETED"}:
                break
            assert final_status not in {"FAILED", "CANCELLED", "CLEANED_UP"}, (
                f"Execution ended unsuccessfully: {final_status}"
            )
            time.sleep(2)
        assert final_status in {"RUNNING", "COMPLETED"}, "Execution status timed out after 180 seconds"
        assert target_url and target_url.startswith("http://"), "Runtime Host did not return a target URL"

        ok, logs = runtime_client.get_job_logs(run_job_id)
        assert ok, f"Runtime Host log retrieval failed: {logs}"
        assert isinstance(logs, str), "Runtime Host returned malformed execution logs"
    finally:
        # Cleanup uses a fresh one-shot capability and runs even if build/run/assertions fail.
        cleanup_token = authorization.issue_mutation_token(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            operation="cleanup",
            worker_cert_subject=live_identity["worker_subject"],
            audience=audience,
            job_id=cleanup_job_id,
        )
        cleanup = _dispatch(
            orchestrator,
            cleanup_token,
            {
                "idempotency_key": f"{request_id}:cleanup",
                "job_id": cleanup_job_id,
                "tenant_id": tenant_id,
                "assessment_id": assessment_id,
                "operation": "cleanup",
                "resources": resources,
                "resource_limits": {},
                "image_tag": f"sentinelx-app-{short_id}",
                "container_name": f"sentinelx-cont-{short_id}",
                "network_name": f"sentinelx-net-{short_id}",
            },
        )
        assert cleanup.get("status") == "CANCELLED", (
            f"Runtime Host cleanup failed: {cleanup}"
        )
