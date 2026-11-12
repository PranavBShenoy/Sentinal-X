"""
Unit tests for Runtime Host FastAPI endpoints (Phase A).

Verifies:
- Every protected endpoint rejects unauthenticated requests.
- Invalid JWTs are rejected.
- Read tokens cannot perform mutations.
- Health check is unauthenticated and reveals no secrets.

No Docker daemon required — uses mocked Authenticator and JobStore.
"""

from __future__ import annotations

import sys
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_BACKEND = str(Path(__file__).resolve().parent.parent.parent / "backend")
_RUNTIME_HOST = str(Path(__file__).resolve().parent.parent.parent / "runtime_host")
for _p in (_BACKEND, _RUNTIME_HOST):
    if _p in sys.path:
        sys.path.remove(_p)
sys.path.insert(0, _BACKEND)
sys.path.insert(1, _RUNTIME_HOST)


from app.runtime.job_token import (
    generate_ed25519_keypair,
    serialize_public_key,
    sign_job_token,
)
from fastapi import HTTPException
import httpx

from runtime_host.app.auth import AuthContext
from runtime_host.app.config import ConfigError
from runtime_host.app.main import create_app
from runtime_host.tests.cert_utils import cert_pem, make_ca

TEST_PROXY_TOKEN = "test-proxy-token-0123456789abcdef"


class LocalASGITestClient:
    """Synchronous test facade that avoids the environment's broken AnyIO portal."""

    def __init__(self, app):
        self.app = app
        self.loop = None
        self.lifespan = None

    def __enter__(self):
        self.loop = asyncio.new_event_loop()
        self.lifespan = self.app.router.lifespan_context(self.app)
        self.loop.run_until_complete(self.lifespan.__aenter__())
        return self

    def __exit__(self, exc_type, exc, tb):
        self.loop.run_until_complete(self.lifespan.__aexit__(exc_type, exc, tb))
        self.loop.close()

    async def _request(self, method, url, **kwargs):
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, url, **kwargs)

    def get(self, url, **kwargs):
        return self.loop.run_until_complete(self._request("GET", url, **kwargs))

    def post(self, url, **kwargs):
        return self.loop.run_until_complete(self._request("POST", url, **kwargs))


def _client_ca_pem() -> bytes:
    _, ca_cert = make_ca()
    return cert_pem(ca_cert)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_token(
    private_key,
    *,
    operation: str = "build",
    token_type: str = "mutation",
    tenant_id: str = "t-tenant1",
    assessment_id: str = "a-assessment1",
    job_id: str = "j-job1",
    audience: str | None = None,
    issuer: str = "sentinelx-authorization",
    jti: str | None = None,
    ttl_seconds: int = 300,
) -> str:
    import uuid

    return sign_job_token(
        private_key,
        jti=jti or str(uuid.uuid4()),
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        job_id=job_id,
        operation=operation,
        resources=["sentinelx-cont-a-assessment1"],
        resource_limits={},
        token_type=token_type,
        ttl_seconds=ttl_seconds,
        audience=audience,
        issuer=issuer,
    )


def _make_auth_context(
    *,
    token_type: str = "mutation",
    tenant_id: str = "t-tenant1",
    assessment_id: str = "a-assessment1",
    job_id: str = "j-job1",
    operation: str = "build",
    jti: str = "jti-abc123",
) -> AuthContext:
    return AuthContext(
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        job_id=job_id,
        operation=operation,
        jti=jti,
        token_type=token_type,
        resources=["sentinelx-cont-a-assessment1"],
        resource_limits={},
        aud=None,
    )


def _make_app():
    """Create a test FastAPI app with a valid public key."""
    _, public_key = generate_ed25519_keypair()
    pem = serialize_public_key(public_key)
    return create_app(
        public_key_pem=pem,
        proxy_token=TEST_PROXY_TOKEN,
        client_ca_pem=_client_ca_pem(),
    )


def _set_authenticator(mock_auth):
    """Set the global authenticator on the main module."""
    import runtime_host.app.main as main_mod

    main_mod._authenticator = mock_auth


# ---------------------------------------------------------------------------
# Endpoint tests
# ---------------------------------------------------------------------------

class TestEndpointsRequireAuthentication:
    def test_submit_job_rejects_unauthenticated(self):
        """POST /submit with no auth raises 401."""
        app = _make_app()
        with LocalASGITestClient(app) as client:
            # Lifespan has started; override the global authenticator now
            mock_auth = MagicMock()
            mock_auth.authenticate = AsyncMock(
                side_effect=HTTPException(
                    status_code=401, detail="Missing job capability token"
                )
            )
            _set_authenticator(mock_auth)

            resp = client.post(
                "/v1/runtime/jobs/submit",
                json={
                    "idempotency_key": "ik-1",
                    "job_id": "j-1",
                    "tenant_id": "t-1",
                    "assessment_id": "a-1",
                    "operation": "build",
                    "resources": [],
                    "resource_limits": {},
                    "cpu_limit": "1.0",
                    "mem_limit": "512m",
                    "drop_capabilities": ["ALL"],
                    "no_new_privileges": True,
                    "read_only_rootfs": True,
                },
            )
        assert resp.status_code == 401

    def test_get_status_rejects_unauthenticated(self):
        """GET /status with no auth raises 401."""
        app = _make_app()
        with LocalASGITestClient(app) as client:
            mock_auth = MagicMock()
            mock_auth.authenticate = AsyncMock(
                side_effect=HTTPException(
                    status_code=401, detail="Missing job capability token"
                )
            )
            _set_authenticator(mock_auth)

            resp = client.get("/v1/runtime/jobs/j-1/status")
        assert resp.status_code == 401

    def test_get_logs_rejects_unauthenticated(self):
        """GET /logs with no auth raises 401."""
        app = _make_app()
        with LocalASGITestClient(app) as client:
            mock_auth = MagicMock()
            mock_auth.authenticate = AsyncMock(
                side_effect=HTTPException(
                    status_code=401, detail="Missing job capability token"
                )
            )
            _set_authenticator(mock_auth)

            resp = client.get("/v1/runtime/jobs/j-1/logs")
        assert resp.status_code == 401

    def test_cancel_job_rejects_unauthenticated(self):
        """POST /cancel with no auth raises 401."""
        app = _make_app()
        with LocalASGITestClient(app) as client:
            mock_auth = MagicMock()
            mock_auth.authenticate = AsyncMock(
                side_effect=HTTPException(
                    status_code=401, detail="Missing job capability token"
                )
            )
            _set_authenticator(mock_auth)

            resp = client.post("/v1/runtime/jobs/j-1/cancel")
        assert resp.status_code == 401

    def test_health_check_allows_unauthenticated(self):
        """GET /health is unauthenticated and returns status without secrets."""
        app = _make_app()
        with LocalASGITestClient(app) as client:
            resp = client.get("/v1/runtime/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "docker_available" in data
        # No secrets exposed
        body = str(data).lower()
        assert "token" not in body
        assert "key" not in body
        assert "secret" not in body
        assert "password" not in body


class TestTokenTypeEnforcement:
    def test_submit_job_requires_mutation_token(self):
        """submit_job with read token returns 403."""
        private_key, public_key = generate_ed25519_keypair()
        pem = serialize_public_key(public_key)
        app = create_app(
            public_key_pem=pem,
            proxy_token=TEST_PROXY_TOKEN,
            client_ca_pem=_client_ca_pem(),
        )

        read_ctx = _make_auth_context(token_type="read")
        with LocalASGITestClient(app) as client:
            _set_authenticator(
                MagicMock(authenticate=AsyncMock(return_value=read_ctx))
            )
            with patch("runtime_host.app.main._job_store") as mock_store:
                mock_store.get_job_by_idempotency_key = MagicMock(return_value=None)
                token = _make_token(private_key, token_type="read")
                resp = client.post(
                    "/v1/runtime/jobs/submit",
                    json={
                        "idempotency_key": "ik-1",
                        "job_id": "j-1",
                        "tenant_id": "t-1",
                        "assessment_id": "a-1",
                        "operation": "build",
                        "resources": [],
                        "resource_limits": {},
                        "cpu_limit": "1.0",
                        "mem_limit": "512m",
                        "drop_capabilities": ["ALL"],
                        "no_new_privileges": True,
                        "read_only_rootfs": True,
                    },
                    headers={"Authorization": f"Bearer {token}"},
                )
        assert resp.status_code == 403

    def test_get_status_requires_read_token(self):
        """get_status with mutation token returns 403."""
        private_key, public_key = generate_ed25519_keypair()
        pem = serialize_public_key(public_key)
        app = create_app(
            public_key_pem=pem,
            proxy_token=TEST_PROXY_TOKEN,
            client_ca_pem=_client_ca_pem(),
        )

        mut_ctx = _make_auth_context(token_type="mutation")
        with LocalASGITestClient(app) as client:
            _set_authenticator(
                MagicMock(authenticate=AsyncMock(return_value=mut_ctx))
            )
            token = _make_token(private_key, token_type="mutation")
            resp = client.get(
                "/v1/runtime/jobs/j-1/status",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 403

    def test_get_logs_requires_read_token(self):
        """get_logs with mutation token returns 403."""
        private_key, public_key = generate_ed25519_keypair()
        pem = serialize_public_key(public_key)
        app = create_app(
            public_key_pem=pem,
            proxy_token=TEST_PROXY_TOKEN,
            client_ca_pem=_client_ca_pem(),
        )

        mut_ctx = _make_auth_context(token_type="mutation")
        with LocalASGITestClient(app) as client:
            _set_authenticator(
                MagicMock(authenticate=AsyncMock(return_value=mut_ctx))
            )
            token = _make_token(private_key, token_type="mutation")
            resp = client.get(
                "/v1/runtime/jobs/j-1/logs",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 403

    def test_cancel_job_requires_mutation_token(self):
        """cancel_job with read token returns 403."""
        private_key, public_key = generate_ed25519_keypair()
        pem = serialize_public_key(public_key)
        app = create_app(
            public_key_pem=pem,
            proxy_token=TEST_PROXY_TOKEN,
            client_ca_pem=_client_ca_pem(),
        )

        read_ctx = _make_auth_context(token_type="read")
        with LocalASGITestClient(app) as client:
            _set_authenticator(
                MagicMock(authenticate=AsyncMock(return_value=read_ctx))
            )
            token = _make_token(private_key, token_type="read")
            resp = client.post(
                "/v1/runtime/jobs/j-1/cancel",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 403


class TestMissingPublicKeyStartup:
    def test_create_app_without_public_key(self, monkeypatch):
        """create_app fails closed when no public key is configured."""
        monkeypatch.delenv("RUNTIME_HOST_PUBLIC_KEY_PATH", raising=False)
        monkeypatch.delenv("RUNTIME_HOST_PROXY_TOKEN", raising=False)

        with pytest.raises(ConfigError, match="RUNTIME_HOST_PUBLIC_KEY_PATH"):
            create_app(public_key_pem=None)


class TestMissingClientCaStartup:
    def _write_env_material(self, tmp_path, monkeypatch):
        _, public_key = generate_ed25519_keypair()
        key_path = tmp_path / "public_key.pem"
        key_path.write_bytes(serialize_public_key(public_key))
        monkeypatch.setenv("RUNTIME_HOST_PUBLIC_KEY_PATH", str(key_path))
        monkeypatch.setenv("RUNTIME_HOST_PROXY_TOKEN", TEST_PROXY_TOKEN)
        monkeypatch.setenv("ENVIRONMENT", "development")

    def test_create_app_without_client_ca(self, tmp_path, monkeypatch):
        """create_app fails closed when no trusted client CA is configured."""
        self._write_env_material(tmp_path, monkeypatch)
        monkeypatch.delenv("RUNTIME_HOST_CLIENT_CA_PATH", raising=False)
        monkeypatch.delenv("RUNTIME_HOST_PROXY_TOKEN_FILE", raising=False)

        with pytest.raises(
            ConfigError, match="RUNTIME_HOST_CLIENT_CA_PATH"
        ):
            create_app(public_key_pem=None)

    def test_create_app_requires_audience_in_production(
        self, tmp_path, monkeypatch
    ):
        self._write_env_material(tmp_path, monkeypatch)
        ca_path = tmp_path / "client_ca.crt"
        _, ca_cert = make_ca()
        ca_path.write_bytes(cert_pem(ca_cert))
        monkeypatch.setenv("RUNTIME_HOST_CLIENT_CA_PATH", str(ca_path))
        monkeypatch.delenv("RUNTIME_HOST_AUDIENCE", raising=False)
        monkeypatch.setenv("ENVIRONMENT", "production")

        with pytest.raises(ConfigError, match="RUNTIME_HOST_AUDIENCE"):
            create_app(public_key_pem=None)
