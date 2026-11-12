"""
Unit tests for Runtime Host authentication (Phase A).

Verifies:
- Authenticator requires a public verification key.
- Invalid JWTs are rejected with 401.
- Expired tokens are rejected with 401.
- Wrong-audience tokens are rejected with 401.
- Valid tokens return an AuthContext with correct claims.
- require_mutation rejects read tokens and accepts mutation tokens.
- require_read rejects mutation tokens and accepts read tokens.
- verify_job_token rejects wrong issuer and accepts correct issuer.
- Missing public key prevents Authenticator construction.

No Docker daemon required.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend/app is importable as 'app' (it has no __init__.py,
# so it's a namespace package that must come before runtime_host/app
# which HAS __init__.py and would otherwise shadow it).
_BACKEND = str(Path(__file__).resolve().parent.parent.parent / "backend")
_RUNTIME_HOST = str(Path(__file__).resolve().parent.parent.parent / "runtime_host")
for _p in (_BACKEND, _RUNTIME_HOST):
    if _p in sys.path:
        sys.path.remove(_p)
sys.path.insert(0, _BACKEND)
sys.path.insert(1, _RUNTIME_HOST)

from unittest.mock import MagicMock

import pytest
from app.runtime.job_token import (
    generate_ed25519_keypair,
    serialize_public_key,
    sign_job_token,
)
from fastapi import HTTPException

from runtime_host.app.auth import (
    AuthContext,
    Authenticator,
    require_mutation,
    require_read,
)
from runtime_host.app.token_verification import verify_job_token

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
    """Sign a job capability token for testing."""
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


# ---------------------------------------------------------------------------
# Authenticator tests
# ---------------------------------------------------------------------------

class TestAuthenticatorConstruction:
    def test_requires_public_key(self):
        """Authenticator must reject missing public key."""
        with pytest.raises(ValueError, match="public_key_pem is required"):
            Authenticator(public_key_pem=b"")

    def test_loads_valid_public_key(self):
        """Authenticator accepts valid Ed25519 public key PEM."""
        _, public_key = generate_ed25519_keypair()
        pem = serialize_public_key(public_key)
        auth = Authenticator(public_key_pem=pem, require_mtls=False)
        assert auth is not None


class TestAuthenticatorAuthenticate:
    def test_rejects_missing_token(self):
        """Missing bearer token raises 401."""
        _, public_key = generate_ed25519_keypair()
        pem = serialize_public_key(public_key)
        auth = Authenticator(public_key_pem=pem, require_mtls=False)
        import asyncio

        request = MagicMock(spec=["headers"])
        request.headers = {}

        with pytest.raises(HTTPException) as exc:
            asyncio.run(auth.authenticate(request, credentials=None))
        assert exc.value.status_code == 401

    def test_rejects_invalid_jwt(self):
        """Invalid JWT raises 401."""
        _, public_key = generate_ed25519_keypair()
        pem = serialize_public_key(public_key)
        auth = Authenticator(public_key_pem=pem, require_mtls=False)
        import asyncio

        request = MagicMock(spec=["headers"])
        request.headers = {}
        creds = MagicMock(spec=["credentials"])
        creds.credentials = "invalid.token.here"

        with pytest.raises(HTTPException) as exc:
            asyncio.run(auth.authenticate(request, credentials=creds))
        assert exc.value.status_code == 401

    def test_rejects_expired_token(self):
        """Expired token raises 401."""
        private_key, public_key = generate_ed25519_keypair()
        pem = serialize_public_key(public_key)
        auth = Authenticator(public_key_pem=pem, require_mtls=False)
        import asyncio

        request = MagicMock(spec=["headers"])
        request.headers = {}
        creds = MagicMock(spec=["credentials"])
        creds.credentials = _make_token(private_key, ttl_seconds=-1)

        with pytest.raises(HTTPException) as exc:
            asyncio.run(auth.authenticate(request, credentials=creds))
        assert exc.value.status_code == 401

    def test_rejects_wrong_audience(self):
        """Token for different audience raises 401."""
        private_key, public_key = generate_ed25519_keypair()
        pem = serialize_public_key(public_key)
        auth = Authenticator(
            public_key_pem=pem,
            expected_audience="runtime-host-a",
            require_mtls=False,
        )
        import asyncio

        request = MagicMock(spec=["headers"])
        request.headers = {}
        creds = MagicMock(spec=["credentials"])
        creds.credentials = _make_token(private_key, audience="runtime-host-b")

        with pytest.raises(HTTPException) as exc:
            asyncio.run(auth.authenticate(request, credentials=creds))
        assert exc.value.status_code == 401

    def test_accepts_valid_token(self):
        """Valid token returns AuthContext with correct claims."""
        private_key, public_key = generate_ed25519_keypair()
        pem = serialize_public_key(public_key)
        auth = Authenticator(public_key_pem=pem, require_mtls=False)
        import asyncio

        request = MagicMock(spec=["headers"])
        request.headers = {}
        creds = MagicMock(spec=["credentials"])
        creds.credentials = _make_token(private_key)

        ctx = asyncio.run(auth.authenticate(request, credentials=creds))
        assert ctx.tenant_id == "t-tenant1"
        assert ctx.assessment_id == "a-assessment1"
        assert ctx.job_id == "j-job1"
        assert ctx.operation == "build"
        assert ctx.token_type == "mutation"


# ---------------------------------------------------------------------------
# require_mutation / require_read tests
# ---------------------------------------------------------------------------

class TestTokenTypeDependencies:
    def test_require_mutation_rejects_read_token(self):
        ctx = _make_auth_context(token_type="read")
        with pytest.raises(HTTPException) as exc:
            require_mutation(ctx)
        assert exc.value.status_code == 403

    def test_require_mutation_accepts_mutation_token(self):
        ctx = _make_auth_context(token_type="mutation")
        result = require_mutation(ctx)
        assert result is ctx

    def test_require_read_rejects_mutation_token(self):
        ctx = _make_auth_context(token_type="mutation")
        with pytest.raises(HTTPException) as exc:
            require_read(ctx)
        assert exc.value.status_code == 403

    def test_require_read_accepts_read_token(self):
        ctx = _make_auth_context(token_type="read")
        result = require_read(ctx)
        assert result is ctx

    def test_require_mutation_rejects_none(self):
        with pytest.raises(HTTPException) as exc:
            require_mutation(None)
        assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# verify_job_token issuer tests
# ---------------------------------------------------------------------------

class TestVerifyJobTokenIssuer:
    def test_rejects_wrong_issuer(self):
        private_key, public_key = generate_ed25519_keypair()
        token = _make_token(private_key, issuer="wrong-issuer")
        with pytest.raises(Exception, match="Issuer mismatch"):
            verify_job_token(
                public_key, token, expected_issuer="sentinelx-authorization"
            )

    def test_accepts_correct_issuer(self):
        private_key, public_key = generate_ed25519_keypair()
        token = _make_token(private_key, issuer="sentinelx-authorization")
        payload = verify_job_token(
            public_key, token, expected_issuer="sentinelx-authorization"
        )
        assert payload["iss"] == "sentinelx-authorization"
