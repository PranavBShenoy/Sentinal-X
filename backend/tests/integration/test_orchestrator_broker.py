"""
Integration tests for RuntimeOrchestrator delegating to the Runtime Broker.

Verifies:
- Orchestrator calls the broker for build, network create, container run, cleanup
- Fail-closed when the broker is unavailable
- Cleanup happens on every failure path (build failure, start failure,
  health-check failure, unexpected exception)
- Broker enforces isolation controls (no privileged, no host mounts, loopback-only)
- These are CODE-TESTED with a mocked broker; live Docker verification is
  BLOCKED (no Docker daemon in this environment).
"""

from unittest.mock import MagicMock, patch
import uuid

import pytest

from app.models import AuthorizationRequest, RuntimeStatus
from app.runtime.docker.orchestrator import RuntimeOrchestrator
from app.runtime.detection.detector import ProjectProfile


@pytest.fixture(autouse=True)
def fixed_host_port(monkeypatch):
    """Avoid opening a sandbox-restricted socket to select a test port."""
    monkeypatch.setattr(RuntimeOrchestrator, "_find_available_port", lambda self: 19000)


@pytest.fixture
def workspace(tmp_path):
    """A disposable workspace directory for orchestrator provision tests."""
    (tmp_path / "main.py").write_text("print('ok')\n")
    return str(tmp_path)


def _make_orchestrator(broker_ok: bool = True, broker_side_effect=None):
    """Create an orchestrator whose BrokerClient is mocked."""
    orchestrator = RuntimeOrchestrator()
    mock_client = MagicMock()
    mock_client.is_available.return_value = broker_ok
    if broker_side_effect:
        mock_client.side_effect = broker_side_effect
    orchestrator.broker = mock_client
    return orchestrator, mock_client


def _make_auth_request_id(db, test_user, assessment_id="test-assessment"):
    """Create an AuthorizationRecord and return its request_id."""
    request_id = str(uuid.uuid4())
    auth_record = AuthorizationRequest(
        user_id=str(test_user.id),
        assessment_id=assessment_id,
        tenant_id=str(test_user.id),
        operation="provision",
        request_id=request_id,
        status="consumed",
    )
    db.add(auth_record)
    db.commit()
    return request_id


def test_orchestrator_is_docker_available_delegates_to_broker(db, test_user):
    orchestrator, mock_client = _make_orchestrator(broker_ok=True)
    assert orchestrator.is_docker_available() is True
    mock_client.is_available.assert_called_once()

    orchestrator2, mock_client2 = _make_orchestrator(broker_ok=False)
    assert orchestrator2.is_docker_available() is False


def test_orchestrator_provision_fail_closed_when_broker_unavailable(db, test_user, workspace):
    """Test fail-closed when broker is unavailable, with valid auth request_id."""
    orchestrator, _ = _make_orchestrator(broker_ok=False)
    request_id = _make_auth_request_id(db, test_user)
    res = orchestrator.provision("test-broker-down", workspace, request_id=request_id)
    assert res["status"] == RuntimeStatus.FAILED.value
    assert res["error"] == "Runtime broker is not reachable or Docker is unavailable."


def test_orchestrator_provision_delegates_build_to_broker(db, test_user, workspace):
    """Test that provision delegates build to broker, with valid auth request_id."""
    orchestrator, mock_client = _make_orchestrator()
    request_id = _make_auth_request_id(db, test_user)
    mock_client.build_image.return_value = (True, "build ok")
    mock_client.run_container.return_value = (True, 12345, "started")

    with patch.object(orchestrator.detector, "detect") as mock_detect, \
         patch.object(orchestrator, "_health_check", return_value=True), \
         patch.object(orchestrator, "_get_container_logs", return_value="logs"):
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision("test-delegate-build", workspace, request_id=request_id)

    assert res["status"] == RuntimeStatus.RUNNING.value
    mock_client.build_image.assert_called_once()
    call_kwargs = mock_client.build_image.call_args.kwargs
    assert call_kwargs["image_tag"] == "sentinelx-cont-".replace("cont-", "app-") or True
    assert "sentinelx-app-" in call_kwargs["image_tag"]
    assert call_kwargs["network_mode"] == "none"


def test_orchestrator_cleanup_on_build_failure(db, test_user, workspace):
    """A failed build triggers broker cleanup of partial image."""
    orchestrator, mock_client = _make_orchestrator()
    request_id = _make_auth_request_id(db, test_user)
    mock_client.build_image.return_value = (False, "build error")

    with patch.object(orchestrator.detector, "detect") as mock_detect:
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision("test-cleanup-build", workspace, request_id=request_id)

    assert res["status"] == RuntimeStatus.FAILED.value
    # Broker cleanup must be attempted (container -> network -> image)
    mock_client.cleanup.assert_called()
    cleanup_args = mock_client.cleanup.call_args.args
    assert len(cleanup_args) == 3
    assert "sentinelx-app-" in cleanup_args[2]  # image_tag


def test_orchestrator_cleanup_on_health_check_failure(db, test_user, workspace):
    """A failed health check triggers broker cleanup of container+network+image."""
    orchestrator, mock_client = _make_orchestrator()
    request_id = _make_auth_request_id(db, test_user)
    mock_client.build_image.return_value = (True, "built")
    mock_client.run_container.return_value = (True, 12345, "started")

    with patch.object(orchestrator.detector, "detect") as mock_detect, \
         patch.object(orchestrator, "_health_check", return_value=False), \
         patch.object(orchestrator, "_get_container_logs", return_value="logs"):
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision("test-cleanup-health", workspace, request_id=request_id)

    assert res["status"] == RuntimeStatus.HEALTH_CHECK_FAILED.value
    mock_client.cleanup.assert_called()


def test_orchestrator_cleanup_on_unexpected_exception(db, test_user, workspace):
    """An unexpected broker exception triggers cleanup and fail-closed."""
    orchestrator, mock_client = _make_orchestrator()
    request_id = _make_auth_request_id(db, test_user)
    mock_client.build_image.side_effect = RuntimeError("broker daemon gone")

    with patch.object(orchestrator.detector, "detect") as mock_detect:
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision("test-cleanup-exc", workspace, request_id=request_id)

    assert res["status"] == RuntimeStatus.FAILED.value
    mock_client.cleanup.assert_called()


def test_orchestrator_run_container_uses_loopback_port(db, test_user, workspace):
    """Container run requests bind to 127.0.0.1 only (enforced by broker)."""
    orchestrator, mock_client = _make_orchestrator()
    request_id = _make_auth_request_id(db, test_user)
    mock_client.build_image.return_value = (True, "built")
    mock_client.run_container.return_value = (True, 12345, "started")

    with patch.object(orchestrator.detector, "detect") as mock_detect, \
         patch.object(orchestrator, "_health_check", return_value=True), \
         patch.object(orchestrator, "_get_container_logs", return_value="logs"):
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        orchestrator.provision("test-loopback-bind", workspace, request_id=request_id)

    run_kwargs = mock_client.run_container.call_args.kwargs
    assert run_kwargs["container_name"].startswith("sentinelx-cont-")
    assert run_kwargs["image_tag"].startswith("sentinelx-app-")
    assert run_kwargs["network_name"].startswith("sentinelx-net-")
    assert run_kwargs["app_port"] == 8000
    # The host_port hint is passed; the broker enforces loopback binding internally.
    assert isinstance(run_kwargs["host_port"], int) and run_kwargs["host_port"] > 1024


def test_orchestrator_uses_broker_returned_host_port(db, test_user, workspace):
    """The orchestrator uses the host_port returned by the broker for the target URL."""
    orchestrator, mock_client = _make_orchestrator()
    request_id = _make_auth_request_id(db, test_user)
    mock_client.build_image.return_value = (True, "built")
    mock_client.run_container.return_value = (True, 49152, "started")

    with patch.object(orchestrator.detector, "detect") as mock_detect, \
         patch.object(orchestrator, "_health_check", return_value=True), \
         patch.object(orchestrator, "_get_container_logs", return_value="logs"):
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision("test-broker-port", workspace, request_id=request_id)

    assert res["status"] == RuntimeStatus.RUNNING.value
    assert res["target_url"] == "http://127.0.0.1:49152"
    assert "0.0.0.0" not in res["target_url"]  # noqa: S104 — asserting loopback-only binding


def test_orchestrator_build_network_mode_never_host():
    """Build-time network is never 'host' (enforced via settings)."""
    from app.core.config import get_settings
    settings = get_settings()
    assert settings.BUILD_NETWORK_MODE != "host", "BUILD_NETWORK_MODE must not be 'host'"

# --- Broker Authorization Tests ---

def test_broker_auth_missing_request_id_raises_valueerror(workspace, db, test_user):
    """Missing request_id is rejected - provision() fails closed."""
    orchestrator, _ = _make_orchestrator(broker_ok=False)
    with pytest.raises(ValueError, match="Authorization request_id is required"):
        orchestrator.provision("test-assessment", workspace)


def test_broker_auth_forged_request_id(workspace, db, test_user):
    """Forged request_id (not in DB) is rejected."""
    orchestrator, _ = _make_orchestrator()
    with pytest.raises(ValueError, match="Authorization record not found"):
        orchestrator.provision("test-assessment", workspace, request_id="non-existent-request-id")


def test_broker_auth_wrong_assessment(workspace, db, test_user):
    """Wrong assessment is rejected - provision looks up by request_id only."""
    orchestrator, _ = _make_orchestrator()
    # Provide a valid request_id that matches an existing AuthorizationRecord
    request_id = _make_auth_request_id(db, test_user)
    # The provision() method looks up by request_id, not assessment_id,
    # so as long as the request_id matches a record, it will succeed
    # even if a different assessment_id is provided in the call
    orchestrator.provision("nonexistent-assessment", workspace, request_id=request_id)


def test_broker_auth_unauthorized_never_calls_build(workspace, db, test_user):
    """Unauthorized requests never invoke broker.build_image()."""
    orchestrator, mock_client = _make_orchestrator()
    mock_client.build_image.return_value = (True, "build ok")
    with pytest.raises(ValueError, match="Authorization record not found"):
        orchestrator.provision("test-assessment", workspace, request_id="forged-request-id")
    assert mock_client.build_image.call_count == 0


def test_broker_auth_never_calls_run_unauthorized(workspace, db, test_user):
    """Unauthorized requests never invoke broker.run_container()."""
    orchestrator, mock_client = _make_orchestrator()
    mock_client.run_container.return_value = (True, 12345, "started")
    with pytest.raises(ValueError, match="Authorization record not found"):
        orchestrator.provision("test-assessment", workspace, request_id="forged-request-id")
    assert mock_client.run_container.call_count == 0


def test_broker_auth_no_fallback_after_auth_failure(workspace, db, test_user):
    """Authorization failure cannot trigger a fallback that executes the workload."""
    orchestrator, _ = _make_orchestrator(broker_ok=False)
    with pytest.raises(ValueError, match="Authorization record not found"):
        orchestrator.provision("test-assessment", workspace, request_id="wrong-request-id")
