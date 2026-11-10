"""
Unit tests for Runtime Broker authentication.

Verifies:
- Valid broker key is accepted
- Missing key is rejected (401)
- Invalid key is rejected (401)
- Auth can be disabled (dev-only) via BROKER_AUTH_REQUIRED=False
- Auth required but no key configured fails closed (500)
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException, status
from fastapi.testclient import TestClient

from app.runtime.broker.auth import require_broker_key, validate_broker_key_header
from app.runtime.broker.app import app


class FakeRequest:
    """Minimal request-like object with headers for auth dependency tests."""

    def __init__(self, headers: dict) -> None:
        self.headers = headers


client = TestClient(app)


def test_broker_auth_valid_key_accepted():
    """A valid X-Broker-Key allows the request through."""
    with patch("app.runtime.broker.auth.settings.BROKER_API_KEY", "super-secret-key"), \
         patch("app.runtime.broker.auth.settings.BROKER_AUTH_REQUIRED", True):
        req = FakeRequest({"X-Broker-Key": "super-secret-key"})
        require_broker_key(req)  # should not raise


def test_broker_auth_missing_key_rejected():
    """A missing X-Broker-Key is rejected with 401."""
    with patch("app.runtime.broker.auth.settings.BROKER_API_KEY", "super-secret-key"), \
         patch("app.runtime.broker.auth.settings.BROKER_AUTH_REQUIRED", True):
        req = FakeRequest({})
        with pytest.raises(HTTPException) as exc:
            require_broker_key(req)
        assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_broker_auth_invalid_key_rejected():
    """An invalid X-Broker-Key is rejected with 401."""
    with patch("app.runtime.broker.auth.settings.BROKER_API_KEY", "super-secret-key"), \
         patch("app.runtime.broker.auth.settings.BROKER_AUTH_REQUIRED", True):
        req = FakeRequest({"X-Broker-Key": "wrong-key"})
        with pytest.raises(HTTPException) as exc:
            require_broker_key(req)
        assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_broker_auth_endpoint_rejects_without_key():
    """The /health endpoint without a key returns 401 when auth required."""
    with patch("app.runtime.broker.auth.settings.BROKER_API_KEY", "super-secret-key"), \
         patch("app.runtime.broker.auth.settings.BROKER_AUTH_REQUIRED", True):
        resp = client.get("/v1/broker/health")
        assert resp.status_code == 401


def test_broker_auth_endpoint_accepts_with_valid_key():
    """The /health endpoint with a valid key returns 200 (broker may be down but auth passes)."""
    with patch("app.runtime.broker.auth.settings.BROKER_API_KEY", "super-secret-key"), \
         patch("app.runtime.broker.auth.settings.BROKER_AUTH_REQUIRED", True):
        resp = client.get("/v1/broker/health", headers={"X-Broker-Key": "super-secret-key"})
        # Auth passes; docker_available may be False in this env, but status is not 401
        assert resp.status_code != 401


def test_broker_auth_disabled_dev_only():
    """When BROKER_AUTH_REQUIRED=False, no key is needed (development only)."""
    with patch("app.runtime.broker.auth.settings.BROKER_AUTH_REQUIRED", False), \
         patch("app.runtime.broker.auth.settings.BROKER_API_KEY", ""):
        req = FakeRequest({})
        require_broker_key(req)  # should not raise


def test_broker_auth_required_but_no_key_fails_closed():
    """Auth required with no BROKER_API_KEY configured -> fail closed (500)."""
    with patch("app.runtime.broker.auth.settings.BROKER_API_KEY", ""), \
         patch("app.runtime.broker.auth.settings.BROKER_AUTH_REQUIRED", True):
        req = FakeRequest({"X-Broker-Key": "anything"})
        with pytest.raises(HTTPException) as exc:
            require_broker_key(req)
        assert exc.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


def test_validate_broker_key_header_raw():
    """validate_broker_key_header works with a raw header string."""
    with patch("app.runtime.broker.auth.settings.BROKER_API_KEY", "key-123"), \
         patch("app.runtime.broker.auth.settings.BROKER_AUTH_REQUIRED", True):
        validate_broker_key_header("key-123")  # valid
        with pytest.raises(HTTPException):
            validate_broker_key_header("wrong")  # invalid
        with pytest.raises(HTTPException):
            validate_broker_key_header("")  # missing
