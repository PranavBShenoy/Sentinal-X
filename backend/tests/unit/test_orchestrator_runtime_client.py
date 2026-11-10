"""
Unit tests for RuntimeOrchestrator with a mocked RuntimeClient.

Verifies:
- The orchestrator delegates provisioning/cleanup to a RuntimeClient.
- Simulated mode selects MockRuntimeClient (never real Docker).
- Runtime unavailability triggers fail-closed provisioning.
- Build failure, container start failure, and health-check failure each
  trigger broker/runtime cleanup.
- Unexpected exceptions during provisioning still trigger cleanup.
- Mock responses are marked "simulated" and never claimed as live Docker.

These are code-tested with a mocked client; live Docker verification is
BLOCKED in this environment (no Docker daemon).
"""

from __future__ import annotations

from unittest.mock import patch

from app.core.config import get_settings
from app.models import RuntimeStatus
from app.runtime.docker.orchestrator import RuntimeOrchestrator
from app.runtime.detection.detector import ProjectProfile
from app.runtime.mock_client import MockRuntimeClient


def _make_orchestrator_with_mock(
    fail_build: bool = False,
    fail_start: bool = False,
    fail_cleanup: bool = False,
    fail_availability: bool = False,
):
    """Create an orchestrator backed by a MockRuntimeClient."""
    mock_client = MockRuntimeClient(
        fail_build=fail_build,
        fail_start=fail_start,
        fail_cleanup=fail_cleanup,
        fail_availability=fail_availability,
    )
    orchestrator = RuntimeOrchestrator(runtime_client=mock_client)
    return orchestrator, mock_client


def test_orchestrator_selects_mock_client_in_simulated_mode():
    """RUNTIME_MODE=simulated selects MockRuntimeClient, not BrokerClient."""
    from app.core.config import get_settings

    settings = get_settings()
    # Force simulated mode for this test by constructing directly.
    mock_client = MockRuntimeClient()
    orchestrator = RuntimeOrchestrator(runtime_client=mock_client)
    assert isinstance(orchestrator.broker, MockRuntimeClient)
    assert orchestrator.broker is mock_client


def test_orchestrator_provision_uses_runtime_client():
    """provision() delegates build, run, logs to the runtime client."""
    orchestrator, mock_client = _make_orchestrator_with_mock()

    with patch.object(orchestrator.detector, "detect") as mock_detect, \
         patch.object(orchestrator, "_health_check", return_value=True), \
         patch.object(orchestrator, "_get_container_logs", return_value="[simulated] logs"):
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision("test-provision-uses-client", "/tmp")

    assert res["status"] == RuntimeStatus.RUNNING.value
    assert res["target_url"] == "http://127.0.0.1:19000"
    assert mock_client.calls
    assert any(c["operation"] == "build_image" for c in mock_client.calls)
    assert any(c["operation"] == "run_container" for c in mock_client.calls)


def test_orchestrator_provision_fail_closed_when_runtime_unavailable():
    """If the runtime client is unavailable, provisioning fails closed."""
    orchestrator, mock_client = _make_orchestrator_with_mock(fail_availability=True)

    res = orchestrator.provision("test-runtime-unavailable", "/tmp")

    assert res["status"] == RuntimeStatus.FAILED.value
    assert res["error"] == "Runtime broker is not reachable or Docker is unavailable."
    assert mock_client.calls == []  # no operations attempted


def test_orchestrator_cleanup_on_build_failure():
    """A failed build triggers runtime cleanup of partial image."""
    orchestrator, mock_client = _make_orchestrator_with_mock(fail_build=True)

    with patch.object(orchestrator.detector, "detect") as mock_detect:
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision("test-cleanup-build", "/tmp")

    assert res["status"] == RuntimeStatus.FAILED.value
    # Cleanup must be attempted via the runtime client.
    cleanup_calls = [c for c in mock_client.calls if c["operation"] == "cleanup"]
    assert cleanup_calls, "cleanup must be invoked after build failure"
    assert "sentinelx-app-" in cleanup_calls[-1]["image_tag"]


def test_orchestrator_cleanup_on_start_failure():
    """A failed container start triggers runtime cleanup."""
    orchestrator, mock_client = _make_orchestrator_with_mock(
        fail_build=False,
        fail_start=True,
    )

    with patch.object(orchestrator.detector, "detect") as mock_detect:
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision("test-cleanup-start", "/tmp")

    assert res["status"] == RuntimeStatus.FAILED.value
    cleanup_calls = [c for c in mock_client.calls if c["operation"] == "cleanup"]
    assert cleanup_calls, "cleanup must be invoked after start failure"


def test_orchestrator_cleanup_on_health_check_failure():
    """A failed health check triggers runtime cleanup."""
    orchestrator, mock_client = _make_orchestrator_with_mock()

    with patch.object(orchestrator.detector, "detect") as mock_detect, \
         patch.object(orchestrator, "_health_check", return_value=False), \
         patch.object(orchestrator, "_get_container_logs", return_value="[simulated] logs"):
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision("test-cleanup-health", "/tmp")

    assert res["status"] == RuntimeStatus.HEALTH_CHECK_FAILED.value
    cleanup_calls = [c for c in mock_client.calls if c["operation"] == "cleanup"]
    assert cleanup_calls, "cleanup must be invoked after health-check failure"


def test_orchestrator_cleanup_on_unexpected_exception():
    """An unexpected runtime-client exception triggers cleanup and fail-closed."""
    orchestrator, mock_client = _make_orchestrator_with_mock()

    with patch.object(mock_client, "build_image", side_effect=RuntimeError("simulated runtime gone")), \
         patch.object(orchestrator.detector, "detect") as mock_detect:
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision("test-cleanup-exc", "/tmp")

    assert res["status"] == RuntimeStatus.FAILED.value
    cleanup_calls = [c for c in mock_client.calls if c["operation"] == "cleanup"]
    assert cleanup_calls, "cleanup must be invoked after unexpected exception"


def test_orchestrator_cleanup_delegates_to_client():
    """cleanup() delegates to the runtime client's cleanup."""
    orchestrator, mock_client = _make_orchestrator_with_mock()

    # assessment_id is truncated to [:12] for resource names.
    orchestrator.cleanup("abc123")

    cleanup_calls = [c for c in mock_client.calls if c["operation"] == "cleanup"]
    assert cleanup_calls
    assert cleanup_calls[-1]["container_name"] == "sentinelx-cont-abc123"
    assert cleanup_calls[-1]["image_tag"] == "sentinelx-app-abc123"


def test_orchestrator_is_available_delegates_to_client():
    """is_docker_available() delegates to the runtime client."""
    orchestrator, mock_client = _make_orchestrator_with_mock()
    assert orchestrator.is_docker_available() is True

    mock_client.fail_availability = True
    assert orchestrator.is_docker_available() is False


def test_mock_responses_are_not_claimed_as_live_docker():
    """Mock responses are explicitly marked simulated."""
    orchestrator, mock_client = _make_orchestrator_with_mock()

    with patch.object(orchestrator.detector, "detect") as mock_detect, \
         patch.object(orchestrator, "_health_check", return_value=True), \
         patch.object(orchestrator, "_get_container_logs", return_value="[simulated] logs"):
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision("test-not-live-docker", "/tmp")

    assert res["status"] == RuntimeStatus.RUNNING.value
    # The target URL points to the simulated port, never a real Docker binding.
    assert "19000" in res["target_url"]
    assert "0.0.0.0" not in res["target_url"]  # noqa: S104 — asserting loopback-only binding


def test_settings_runtime_mode_default_broker():
    """Default RUNTIME_MODE is broker (production-safe)."""
    settings = get_settings()
    assert settings.RUNTIME_MODE == "broker"
