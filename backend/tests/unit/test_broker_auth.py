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
from importlib import import_module

import pytest
from fastapi import HTTPException, status

from app.runtime.broker.auth import require_broker_key, validate_broker_key_header
broker_app = import_module("app.runtime.broker.app")
app = broker_app.app


class FakeRequest:
    """Minimal request-like object with headers for auth dependency tests."""

    def __init__(self, headers: dict) -> None:
        self.headers = headers


@pytest.fixture(autouse=True)
def keep_health_test_off_the_docker_daemon(monkeypatch):
    """Health endpoint auth tests must not probe a real daemon."""
    monkeypatch.setattr(broker_app.executor, "is_available", lambda: (False, "disabled in unit test"))


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
    """The health endpoint handler rejects missing auth without an ASGI socket."""
    with patch("app.runtime.broker.auth.settings.BROKER_API_KEY", "super-secret-key"), \
         patch("app.runtime.broker.auth.settings.BROKER_AUTH_REQUIRED", True):
        with pytest.raises(HTTPException) as exc:
            broker_app.broker_health(x_broker_key=None)
        assert exc.value.status_code == 401


def test_broker_auth_endpoint_accepts_with_valid_key():
    """A valid key reaches the handler, with daemon health stubbed off."""
    with patch("app.runtime.broker.auth.settings.BROKER_API_KEY", "super-secret-key"), \
         patch("app.runtime.broker.auth.settings.BROKER_AUTH_REQUIRED", True):
        response = broker_app.broker_health(x_broker_key="super-secret-key")
        assert response.docker_available is False


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
