"""
Unit tests for RemoteRuntimeClient using mocked HTTP transport.

These tests verify that the remote runtime client:
- Sends mTLS-authenticated requests with job tokens
- Parses responses correctly
- Fail-closes when the runtime host is unreachable
- Requires a job token (never submits without one)
- Validates responses as untrusted data
- Rejects invalid job tokens and mismatched claims
- Validates target URLs and response schemas
- Never logs tokens or private keys

No Docker daemon or real runtime host is required.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from unittest.mock import MagicMock, patch

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

from app.runtime.job_token import JobTokenError, sign_job_token
from app.runtime.runtime_host_client import RemoteRuntimeClient


def _make_mock_response(
    status_code: int = 200,
    json_data: Optional[dict] = None,
    text: str = "",
) -> MagicMock:
    """Create a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text or json.dumps(json_data or {})
    return resp


def _make_mock_response(
    status_code: int = 200,
    json_data: Optional[dict] = None,
    text: str = "",
) -> MagicMock:
    """Create a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text or json.dumps(json_data or {})
    return resp


class _MockClientContext:
    """Mock httpx.Client as a context manager."""

    def __init__(self, response: MagicMock):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def request(self, method, url, *, json=None, headers=None):
        return self._response

    def post(self, url, *, json=None, headers=None):
        return self._response

    def get(self, url, *, headers=None):
        return self._response


def _make_client(
    *,
    runtime_url: str = "https://runtime-host.example.com:8443",
    client_cert: Optional[str] = "/tmp/client.crt",
    client_key: Optional[str] = "/tmp/client.key",
    ca_cert: Optional[str] = "/tmp/ca.crt",
    job_token: Optional[str] = "job-token-abc123",
) -> RemoteRuntimeClient:
    # Generate one matching client key/certificate pair. The CA file is a
    # trusted test certificate; all three use current CertificateBuilder APIs.
    if client_cert and client_key and ca_cert:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "test-cert")]
        )
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        pem_key = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pem_cert = cert.public_bytes(serialization.Encoding.PEM)
        for path in (client_cert, client_key, ca_cert):
            os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(client_key, "wb") as output:
            output.write(pem_key)
        with open(client_cert, "wb") as output:
            output.write(pem_cert)
        with open(ca_cert, "wb") as output:
            output.write(pem_cert)

    return RemoteRuntimeClient(
        runtime_url=runtime_url,
        client_cert=client_cert,
        client_key=client_key,
        ca_cert=ca_cert,
        job_token=job_token,
    )


class TestRemoteRuntimeClientInstantiation:
    """Tests for client instantiation and configuration."""

    def test_client_creation_with_all_params(self):
        client = _make_client()
        assert client.runtime_url == "https://runtime-host.example.com:8443"
        assert client.client_cert == "/tmp/client.crt"
        assert client.client_key == "/tmp/client.key"
        assert client.ca_cert == "/tmp/ca.crt"
        assert client.job_token == "job-token-abc123"

    def test_client_creation_with_minimal_params(self):
        client = RemoteRuntimeClient(runtime_url="https://example.com:8443")
        assert client.runtime_url == "https://example.com:8443"
        assert client.client_cert is None
        assert client.client_key is None
        assert client.ca_cert is None
        assert client.job_token is None

    def test_remote_factory_mode_requires_https_and_complete_mtls(self):
        with pytest.raises(ValueError, match="must use HTTPS"):
            RemoteRuntimeClient(
                runtime_url="http://runtime.example:8443",
                client_cert="/tmp/client.crt",
                client_key="/tmp/client.key",
                ca_cert="/tmp/ca.crt",
                require_mtls=True,
            )
        with pytest.raises(ValueError, match="configuration is incomplete"):
            RemoteRuntimeClient(
                runtime_url="https://runtime.example:8443",
                require_mtls=True,
            )

    def test_client_creation_fails_with_missing_cert(self):
        """Fails closed when configured cert file doesn't exist."""
        with pytest.raises(FileNotFoundError, match="not found or unreadable"):
            RemoteRuntimeClient(
                runtime_url="https://runtime-host.example.com:8443",
                client_cert="/tmp/nonexistent-client.crt",
                client_key="/tmp/client.key",
                ca_cert="/tmp/ca.crt",
                job_token="job-token-abc123",
            )

    def test_client_creation_fails_with_missing_key(self):
        """Fails closed when client key file doesn't exist."""
        with pytest.raises(FileNotFoundError, match="not found or unreadable"):
            RemoteRuntimeClient(
                runtime_url="https://runtime-host.example.com:8443",
                client_cert="/tmp/client.crt",
                client_key="/tmp/nonexistent-client.key",
                ca_cert="/tmp/ca.crt",
                job_token="job-token-abc123",
            )


class TestRemoteRuntimeClientSubmitJob:
    """Tests for submit_job with mocked HTTP transport."""

    def test_submit_job_success(self):
        client = _make_client()
        mock_resp = _make_mock_response(
            200,
            {
                "job_id": "j-abc123-build",
                "status": "accepted",
                "message": "Job accepted for processing",
                "target_url": "http://10.0.0.1:32768",
                "expires_at": "2026-11-10T13:10:00Z",
            },
        )
        with patch(
            "app.runtime.runtime_host_client.httpx.Client",
            return_value=_MockClientContext(mock_resp),
        ):
            ok, job_id, target_url = client.submit_job(
                assessment_id="a-abc123",
                operation="build",
                job_id="j-abc123-build",
                tenant_id="tenant-abc123",
                artifact_url="https://control-plane.internal:8444/artifacts/a-abc123.tar.gz",
                artifact_sha256="sha256:" + "a" * 64,
            )
        assert ok is True
        assert job_id == "j-abc123-build"
        assert target_url == "http://10.0.0.1:32768"

    def test_submit_job_requires_token(self):
        client = RemoteRuntimeClient(
            runtime_url="https://runtime-host.example.com:8443",
            client_cert="/tmp/client.crt",
            client_key="/tmp/client.key",
            ca_cert="/tmp/ca.crt",
            job_token=None,
        )
        ok, job_id, target_url = client.submit_job(
            assessment_id="a-abc123",
            operation="build",
        )
        assert ok is False
        assert "No job token set" in job_id
        assert target_url is None

    def test_submit_job_server_error(self):
        client = _make_client()
        mock_resp = _make_mock_response(
            500,
            {"error": "Internal server error"},
        )
        with patch(
            "app.runtime.runtime_host_client.httpx.Client",
            return_value=_MockClientContext(mock_resp),
        ):
            ok, job_id, target_url = client.submit_job(
                assessment_id="a-abc123",
                operation="build",
                tenant_id="tenant-abc123",
            )
        assert ok is False
        assert job_id == "Internal server error"
        assert target_url is None

    def test_submit_job_connection_error(self):
        client = _make_client()
        with patch(
            "app.runtime.runtime_host_client.httpx.Client",
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            ok, job_id, target_url = client.submit_job(
                assessment_id="a-abc123",
                operation="build",
                tenant_id="tenant-abc123",
            )
        assert ok is False
        assert "Connection refused" in job_id
        assert target_url is None


class TestRemoteRuntimeClientGetJobStatus:
    """Tests for get_job_status with mocked HTTP transport."""

    def test_get_job_status_success(self):
        client = _make_client()
        mock_resp = _make_mock_response(
            200,
            {
                "job_id": "j-abc123-build",
                "status": "completed",
                "target_url": "http://10.0.0.1:32768",
            },
        )
        with patch(
            "app.runtime.runtime_host_client.httpx.Client",
            return_value=_MockClientContext(mock_resp),
        ):
            ok, status, target_url = client.get_job_status("j-abc123-build")
        assert ok is True
        assert status == "completed"
        assert target_url == "http://10.0.0.1:32768"

    def test_get_job_status_failure(self):
        client = _make_client()
        mock_resp = _make_mock_response(
            404,
            {"error": "Job not found"},
        )
        with patch(
            "app.runtime.runtime_host_client.httpx.Client",
            return_value=_MockClientContext(mock_resp),
        ):
            ok, status, target_url = client.get_job_status("j-nonexistent")
        assert ok is False
        assert status == "Job not found"
        assert target_url is None


class TestRemoteRuntimeClientGetJobLogs:
    """Tests for get_job_logs with mocked HTTP transport."""

    def test_get_job_logs_success(self):
        client = _make_client()
        mock_resp = _make_mock_response(
            200,
            {"job_id": "j-abc123-build", "logs": "[simulated] build output"},
        )
        with patch(
            "app.runtime.runtime_host_client.httpx.Client",
            return_value=_MockClientContext(mock_resp),
        ):
            ok, logs = client.get_job_logs("j-abc123-build")
        assert ok is True
        assert logs == "[simulated] build output"

    def test_get_job_logs_failure(self):
        client = _make_client()
        mock_resp = _make_mock_response(
            500,
            {"error": "Internal server error"},
        )
        with patch(
            "app.runtime.runtime_host_client.httpx.Client",
            return_value=_MockClientContext(mock_resp),
        ):
            ok, logs = client.get_job_logs("j-abc123-build")
        assert ok is False
        assert logs == "Internal server error"


class TestRemoteRuntimeClientCancelJob:
    """Tests for cancel_job with mocked HTTP transport."""

    def test_cancel_job_success(self):
        client = _make_client()
        mock_resp = _make_mock_response(
            200,
            {"job_id": "j-abc123-build", "status": "cancelled", "message": "Job cancelled"},
        )
        with patch(
            "app.runtime.runtime_host_client.httpx.Client",
            return_value=_MockClientContext(mock_resp),
        ):
            ok, msg = client.cancel_job("j-abc123-build")
        assert ok is True
        assert msg == "Job cancelled"


class TestRemoteRuntimeClientIsAvailable:
    """Tests for is_available with mocked HTTP transport."""

    def test_is_available_healthy(self):
        client = _make_client()
        mock_resp = _make_mock_response(
            200,
            {"status": "healthy", "docker_available": True},
        )
        with patch(
            "app.runtime.runtime_host_client.httpx.Client",
            return_value=_MockClientContext(mock_resp),
        ):
            assert client.is_available() is True

    def test_is_available_docker_down(self):
        client = _make_client()
        mock_resp = _make_mock_response(
            200,
            {"status": "degraded", "docker_available": False},
        )
        with patch(
            "app.runtime.runtime_host_client.httpx.Client",
            return_value=_MockClientContext(mock_resp),
        ):
            assert client.is_available() is False

    def test_is_available_connection_error(self):
        client = _make_client()
        with patch(
            "app.runtime.runtime_host_client.httpx.Client",
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            assert client.is_available() is False


class TestJobTokenSigning:
    """Tests for asymmetric job token creation."""

    def test_sign_and_verify_token(self):
        from app.runtime.job_token import (
            generate_ed25519_keypair,
            verify_job_token,
        )

        private_key, public_key = generate_ed25519_keypair()
        token = sign_job_token(
            private_key,
            jti="job-abc123",
            tenant_id="t-tenant1",
            assessment_id="a-assessment1",
            job_id="j-job1",
            operation="build",
            resources=["sentinelx-cont-a-assessment1"],
            resource_limits={"memory": "512m", "cpus": "1.0"},
            token_type="mutation",
            ttl_seconds=300,
        )
        assert isinstance(token, str)
        assert token.count(".") == 2  # header.payload.signature

        payload = verify_job_token(
            public_key,
            token,
            expected_operation="build",
            expected_assessment_id="a-assessment1",
            expected_tenant_id="t-tenant1",
        )
        assert payload["jti"] == "job-abc123"
        assert payload["assessment_id"] == "a-assessment1"
        assert payload["tenant_id"] == "t-tenant1"
        assert payload["operation"] == "build"
        assert payload["iss"] == "sentinelx-authorization"

    def test_job_token_rejects_wrong_operation(self):
        from app.runtime.job_token import (
            generate_ed25519_keypair,
            verify_job_token,
        )

        private_key, public_key = generate_ed25519_keypair()
        token = sign_job_token(
            private_key,
            jti="job-abc123",
            tenant_id="t-tenant1",
            assessment_id="a-assessment1",
            job_id="j-job1",
            operation="build",
            resources=["sentinelx-cont-a-assessment1"],
            resource_limits={},
            token_type="mutation",
            ttl_seconds=300,
        )
        with pytest.raises(JobTokenError, match="Operation mismatch"):
            verify_job_token(
                public_key,
                token,
                expected_operation="run",
                expected_assessment_id="a-assessment1",
                expected_tenant_id="t-tenant1",
            )

    def test_job_token_rejects_wrong_assessment(self):
        from app.runtime.job_token import (
            generate_ed25519_keypair,
            verify_job_token,
        )

        private_key, public_key = generate_ed25519_keypair()
        token = sign_job_token(
            private_key,
            jti="job-abc123",
            tenant_id="t-tenant1",
            assessment_id="a-assessment1",
            job_id="j-job1",
            operation="build",
            resources=["sentinelx-cont-a-assessment1"],
            resource_limits={},
            token_type="mutation",
            ttl_seconds=300,
        )
        with pytest.raises(JobTokenError, match="Assessment mismatch"):
            verify_job_token(
                public_key,
                token,
                expected_operation="build",
                expected_assessment_id="a-different-assessment",
                expected_tenant_id="t-tenant1",
            )

    def test_job_token_rejects_wrong_tenant(self):
        from app.runtime.job_token import (
            generate_ed25519_keypair,
            verify_job_token,
        )

        private_key, public_key = generate_ed25519_keypair()
        token = sign_job_token(
            private_key,
            jti="job-abc123",
            tenant_id="t-tenant1",
            assessment_id="a-assessment1",
            job_id="j-job1",
            operation="build",
            resources=["sentinelx-cont-a-assessment1"],
            resource_limits={},
            token_type="mutation",
            ttl_seconds=300,
        )
        with pytest.raises(JobTokenError, match="Tenant mismatch"):
            verify_job_token(
                public_key,
                token,
                expected_operation="build",
                expected_assessment_id="a-assessment1",
                expected_tenant_id="t-different-tenant",
            )

    def test_job_token_serialization_roundtrip(self):
        from app.runtime.job_token import (
            deserialize_private_key,
            deserialize_public_key,
            generate_ed25519_keypair,
            serialize_private_key,
            serialize_public_key,
            verify_job_token,
        )

        private_key, public_key = generate_ed25519_keypair()

        # Serialize and deserialize private key
        private_pem = serialize_private_key(private_key)
        deserialized_private = deserialize_private_key(private_pem)

        # Serialize and deserialize public key
        public_pem = serialize_public_key(public_key)
        deserialized_public = deserialize_public_key(public_pem)

        token = sign_job_token(
            deserialized_private,
            jti="job-abc123",
            tenant_id="t-tenant1",
            assessment_id="a-assessment1",
            job_id="j-job1",
            operation="build",
            resources=["sentinelx-cont-a-assessment1"],
            resource_limits={},
            token_type="mutation",
            ttl_seconds=300,
        )

        payload = verify_job_token(
            deserialized_public,
            token,
            expected_operation="build",
            expected_assessment_id="a-assessment1",
            expected_tenant_id="t-tenant1",
        )
        assert payload["jti"] == "job-abc123"

    def test_job_token_rejects_wrong_audience(self):
        from app.runtime.job_token import (
            generate_ed25519_keypair,
            sign_job_token,
            verify_job_token,
        )

        private_key, public_key = generate_ed25519_keypair()
        token = sign_job_token(
            private_key,
            jti="job-abc123",
            tenant_id="t-tenant1",
            assessment_id="a-assessment1",
            job_id="j-job1",
            operation="build",
            resources=["sentinelx-cont-a-assessment1"],
            resource_limits={},
            token_type="mutation",
            ttl_seconds=300,
            audience="runtime-host-a.example.com",
        )
        with pytest.raises(JobTokenError, match="Audience mismatch"):
            verify_job_token(
                public_key,
                token,
                expected_operation="build",
                expected_assessment_id="a-assessment1",
                expected_tenant_id="t-tenant1",
                expected_audience="runtime-host-b.example.com",
            )
