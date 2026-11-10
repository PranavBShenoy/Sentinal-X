"""
Unit tests for the RuntimeClient abstraction and MockRuntimeClient.

Verifies:
- RuntimeClient cannot be instantiated directly (abstract).
- MockRuntimeClient implements the full RuntimeClient interface.
- Mock responses carry a "simulated" marker and never claim real Docker
  execution.
- Failure-injection flags (build/start/cleanup/availability) work.
- Simulated mode is development/test only (config rejects it in production).
"""

from __future__ import annotations

import pytest
from app.core.config import get_settings, Settings
from app.runtime.client import RuntimeClient
from app.runtime.mock_client import MockRuntimeClient


def test_runtime_client_cannot_be_instantiated():
    """RuntimeClient is abstract and must not be instantiated directly."""
    with pytest.raises(TypeError):
        RuntimeClient()


def test_mock_runtime_client_is_runtime_client():
    """MockRuntimeClient implements the RuntimeClient interface."""
    client = MockRuntimeClient()
    assert isinstance(client, RuntimeClient)


def test_mock_is_available_default_true():
    client = MockRuntimeClient()
    assert client.is_available() is True


def test_mock_is_available_false_when_fail_availability():
    client = MockRuntimeClient(fail_availability=True)
    assert client.is_available() is False


def test_mock_build_image_returns_simulated_success():
    client = MockRuntimeClient()
    ok, log = client.build_image(
        "/tmp/sentinelx/workspaces/assessment-1",
        "sentinelx-app-abc12345",
        network_mode="none",
    )
    assert ok is True
    assert "[simulated]" in log
    assert "no Docker used" in log


def test_mock_build_image_returns_simulated_failure():
    client = MockRuntimeClient(fail_build=True)
    ok, log = client.build_image(
        "/tmp/sentinelx/workspaces/assessment-1",
        "sentinelx-app-abc12345",
    )
    assert ok is False
    assert "[simulated]" in log
    assert "build failed" in log


def test_mock_run_container_returns_simulated_port():
    client = MockRuntimeClient()
    ok, host_port, log = client.run_container(
        "sentinelx-cont-abc12345",
        "sentinelx-app-abc12345",
        "sentinelx-net-abc12345",
        8000,
        12345,
    )
    assert ok is True
    assert isinstance(host_port, int)
    assert host_port == 19000
    assert "[simulated]" in log
    assert "no Docker used" in log


def test_mock_run_container_returns_simulated_failure():
    client = MockRuntimeClient(fail_start=True)
    ok, host_port, log = client.run_container(
        "sentinelx-cont-abc12345",
        "sentinelx-app-abc12345",
        "sentinelx-net-abc12345",
        8000,
        12345,
    )
    assert ok is False
    assert host_port is None
    assert "[simulated]" in log


def test_mock_cleanup_returns_simulated_steps():
    client = MockRuntimeClient()
    result = client.cleanup(
        "sentinelx-cont-abc12345",
        "sentinelx-net-abc12345",
        "sentinelx-app-abc12345",
    )
    assert result["container"]["ok"] is True
    assert result["network"]["ok"] is True
    assert result["image"]["ok"] is True
    assert "[simulated]" in result["container"]["log"]


def test_mock_cleanup_reports_failure_when_fail_cleanup():
    client = MockRuntimeClient(fail_cleanup=True)
    result = client.cleanup(
        "sentinelx-cont-abc12345",
        "sentinelx-net-abc12345",
        "sentinelx-app-abc12345",
    )
    assert result["container"]["ok"] is False
    assert result["network"]["ok"] is False
    assert result["image"]["ok"] is False


def test_mock_get_logs_and_stop_are_simulated():
    client = MockRuntimeClient()
    logs = client.get_logs("sentinelx-cont-abc12345")
    assert "[simulated]" in logs
    assert "no Docker used" in logs

    ok, msg = client.stop_container("sentinelx-cont-abc12345")
    assert ok is True
    assert "[simulated]" in msg


def test_mock_records_calls():
    client = MockRuntimeClient()
    client.build_image("/tmp/sentinelx/workspaces/a1", "sentinelx-app-abc12345")
    client.run_container(
        "sentinelx-cont-abc12345",
        "sentinelx-app-abc12345",
        "sentinelx-net-abc12345",
        8000,
        12345,
    )
    assert len(client.calls) == 2
    assert client.calls[0]["operation"] == "build_image"
    assert client.calls[1]["operation"] == "run_container"


# ---------------------------------------------------------------------------
# Config: simulated mode rejected in production
# ---------------------------------------------------------------------------


def test_runtime_mode_simulated_rejected_in_production():
    """Production must fail startup if RUNTIME_MODE=simulated."""
    with pytest.raises(ValueError, match="not allowed in production"):
        Settings(APP_ENV="production", RUNTIME_MODE="simulated")


def test_runtime_mode_simulated_allowed_in_development():
    """Simulated mode is permitted in development."""
    settings = Settings(APP_ENV="development", RUNTIME_MODE="simulated")
    assert settings.RUNTIME_MODE == "simulated"


def test_runtime_mode_broker_allowed_in_production():
    """Broker mode is allowed in production when a key is configured."""
    settings = Settings(
        APP_ENV="production",
        RUNTIME_MODE="broker",
        BROKER_API_KEY="a" * 32,
    )
    assert settings.RUNTIME_MODE == "broker"


def test_runtime_mode_defaults_to_broker():
    settings = get_settings()
    assert settings.RUNTIME_MODE == "broker"


def test_runtime_mode_simulated_rejected_via_env_vars_in_production(monkeypatch):
    """Env-var-driven production startup rejects simulated mode.

    This is the actual startup path used by Docker Compose: env vars are
    loaded into Settings, and the field validator must reject
    RUNTIME_MODE=simulated when APP_ENV=production.
    """
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("RUNTIME_MODE", "simulated")
    monkeypatch.setenv("BROKER_API_KEY", "a" * 32)
    # Clear the lru_cache so Settings() re-reads environment variables.
    get_settings.cache_clear()
    try:
        with pytest.raises(ValueError, match="not allowed in production"):
            Settings()
    finally:
        get_settings.cache_clear()


def test_runtime_mode_broker_allowed_via_env_vars_in_production(monkeypatch):
    """Env-var-driven production startup accepts RUNTIME_MODE=broker."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("RUNTIME_MODE", "broker")
    monkeypatch.setenv("BROKER_API_KEY", "a" * 32)
    get_settings.cache_clear()
    try:
        settings = Settings()
        assert settings.RUNTIME_MODE == "broker"
    finally:
        get_settings.cache_clear()


def test_get_settings_rejects_simulated_in_production_via_env_vars(monkeypatch):
    """get_settings() (used by the orchestrator's default constructor)
    rejects simulated mode in production when driven by environment variables.

    This is the actual startup path: Docker Compose sets APP_ENV and
    RUNTIME_MODE as env vars; Settings() must reject simulated mode in
    production before any orchestrator can be auto-configured.
    """
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("RUNTIME_MODE", "simulated")
    monkeypatch.setenv("BROKER_API_KEY", "a" * 32)
    get_settings.cache_clear()
    try:
        with pytest.raises(ValueError, match="not allowed in production"):
            get_settings()
    finally:
        get_settings.cache_clear()
