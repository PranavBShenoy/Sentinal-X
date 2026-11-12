"""Security boundary regressions for job submission and Runtime Host access."""

from __future__ import annotations

import asyncio
from fastapi import HTTPException
import pytest
from pydantic import ValidationError
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from app.runtime.broker.schemas import JobSubmitRequest
from app.runtime.runtime_host_client import JobSubmitRequest as RemoteJobSubmitRequest
from app.schemas.schemas import AssessmentConfig
from app.runtime.job_token import generate_ed25519_keypair, serialize_public_key, sign_job_token
from runtime_host.app.schemas import JobSubmitRequest as HostJobSubmitRequest
from runtime_host.app.auth import AuthContext
from runtime_host.app.main import create_app
from runtime_host.app.jobs import JobStore
from runtime_host.app.token_verification import JobTokenError, verify_job_token
from runtime_host.tests.cert_utils import cert_pem, make_ca


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/archive.tar.gz",
        "https://127.0.0.1/archive.tar.gz",
        "https://10.1.2.3/archive.tar.gz",
        "https://172.16.0.1/archive.tar.gz",
        "https://192.168.1.2/archive.tar.gz",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/archive.tar.gz",
        "https://user:pass@example.com/archive.tar.gz",
    ],
)
def test_job_schema_rejects_ssrf_artifact_urls(url):
    for schema in (JobSubmitRequest, RemoteJobSubmitRequest):
        with pytest.raises(ValidationError):
            schema(
                job_id="job-1", tenant_id="tenant-1", assessment_id="assessment-1",
                operation="build", resources=[], idempotency_key="idem-1",
                cpu_limit="1.0", mem_limit="512m", drop_capabilities=["ALL"],
                no_new_privileges=True, read_only_rootfs=True,
                artifact_url=url,
            )
    with pytest.raises(ValidationError):
        AssessmentConfig(artifact_url=url)


@pytest.mark.parametrize(
    "overrides",
    [
        {"cpu_limit": "2.0"},
        {"mem_limit": "1g"},
        {"drop_capabilities": ["NET_ADMIN"]},
        {"drop_capabilities": ["ALL", "NET_ADMIN"]},
        {"no_new_privileges": False},
        {"read_only_rootfs": False},
    ],
)
def test_job_schema_rejects_weakened_execution_security(overrides):
    fields = {
        "job_id": "job-1",
        "tenant_id": "tenant-1",
        "assessment_id": "assessment-1",
        "operation": "run",
        "resources": [],
        "idempotency_key": "idem-1",
        "cpu_limit": "1.0",
        "mem_limit": "512m",
        "drop_capabilities": ["ALL"],
        "no_new_privileges": True,
        "read_only_rootfs": True,
    }
    fields.update(overrides)
    for schema in (JobSubmitRequest, RemoteJobSubmitRequest, HostJobSubmitRequest):
        with pytest.raises(ValidationError):
            schema(**fields)


def _runtime_app(monkeypatch, tmp_path):
    import runtime_host.app.main as main

    _, signing_public = generate_ed25519_keypair()
    ca_key, ca_cert = make_ca()

    class NoDocker:
        def __init__(self, *args, **kwargs):
            pass

        def health_check(self):
            return False

        def get_logs(self, **kwargs):
            return None

        def cancel(self, **kwargs):
            from runtime_host.app.schemas import JobCancelResponse
            return JobCancelResponse(job_id=kwargs["job_id"], status="CANCELLED", message="cancelled")

    monkeypatch.setattr(main, "DockerExecutor", NoDocker)
    monkeypatch.setattr(main, "reconcile_orphaned_jobs", lambda *args, **kwargs: 0)
    app = create_app(
        public_key_pem=serialize_public_key(signing_public),
        expected_audience="runtime-host",
        proxy_token="test-proxy-token-that-is-long-enough-for-validation",
        client_ca_pem=cert_pem(ca_cert),
        job_store_db_path=str(tmp_path / "jobs.db"),
        nonce_store_db_path=str(tmp_path / "nonces.db"),
    )
    return app, main


def test_tenant_a_cannot_poll_or_cancel_tenant_b_job(monkeypatch, tmp_path):
    app, main = _runtime_app(monkeypatch, tmp_path)
    main._job_store = JobStore(str(tmp_path / "tenant-jobs.db"))
    assert main._job_store.create_job(
        job_id="tenant-b-job", idempotency_key="tenant-b-idem",
        tenant_id="tenant-b", assessment_id="assessment-b", operation="run",
        resources=[], resource_limits={},
    )
    status_route = next(r for r in app.routes if getattr(r, "path", "") == "/v1/runtime/jobs/{job_id}/status")
    cancel_route = next(r for r in app.routes if getattr(r, "path", "") == "/v1/runtime/jobs/{job_id}/cancel")
    read_auth = AuthContext(
        tenant_id="tenant-a", assessment_id="assessment-a", job_id="tenant-a-job",
        operation="status", jti="read-a", token_type="read", resources=[],
        resource_limits={}, aud="runtime-host",
    )
    mutation_auth = AuthContext(
        tenant_id="tenant-a", assessment_id="assessment-a", job_id="tenant-a-job",
        operation="cancel", jti="cancel-a", token_type="mutation", resources=[],
        resource_limits={}, aud="runtime-host",
    )
    with pytest.raises(HTTPException) as status_error:
        asyncio.run(status_route.endpoint("tenant-b-job", read_auth))
    assert status_error.value.status_code == 403
    with pytest.raises(HTTPException) as cancel_error:
        asyncio.run(cancel_route.endpoint("tenant-b-job", mutation_auth))
    assert cancel_error.value.status_code == 403


def test_expired_and_tampered_capability_tokens_fail_verification():
    private_key, public_key = generate_ed25519_keypair()
    args = dict(
        jti="jti-1", tenant_id="tenant-1", assessment_id="assessment-1",
        job_id="job-1", operation="build", resources=[], resource_limits={},
        token_type="mutation", audience="runtime-host",
    )
    expired = sign_job_token(private_key, ttl_seconds=-10, **args)
    with pytest.raises(JobTokenError, match="expired"):
        verify_job_token(public_key, expired, expected_operation="build")

    token = sign_job_token(private_key, ttl_seconds=300, **args)
    header, payload, signature = token.split(".")
    tampered = f"{header}.{payload[:-1]}{'A' if payload[-1] != 'A' else 'B'}.{signature}"
    with pytest.raises(JobTokenError):
        verify_job_token(public_key, tampered, expected_operation="build")
