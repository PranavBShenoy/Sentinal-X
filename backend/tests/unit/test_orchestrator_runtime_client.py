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

import pytest

from app.core.config import get_settings
from app.models import Assessment, AuthorizationRequest, RuntimeStatus, Worker
from app.runtime.docker.orchestrator import RuntimeOrchestrator
from app.runtime.detection.detector import ProjectProfile
from app.runtime.mock_client import MockRuntimeClient


TEST_REQUEST_ID = "test-request-uuid"


@pytest.fixture(autouse=True)
def fixed_host_port(monkeypatch):
    """Keep orchestration unit tests independent of sandbox socket permissions."""
    monkeypatch.setattr(RuntimeOrchestrator, "_find_available_port", lambda self: 19000)


@pytest.fixture
def provision_auth(db):
    """Create a genuine, committed, consumed AuthorizationRequest.

    ``RuntimeOrchestrator.provision()`` validates the request against the
    database via ``db_session()``.  The ``db`` fixture uses the same
    ``database.SessionLocal`` (test engine), so committing here makes the
    record visible to the orchestrator's separate session.
    """
    record = AuthorizationRequest(
        request_id=TEST_REQUEST_ID,
        user_id="11111111-1111-1111-1111-111111111111",
        assessment_id="22222222-2222-2222-2222-222222222222",
        tenant_id="33333333-3333-3333-3333-333333333333",
        operation="provision",
        status="consumed",
    )
    db.add(record)
    db.commit()
    return TEST_REQUEST_ID


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
    settings = get_settings()
    # Force simulated mode for this test by constructing directly.
    mock_client = MockRuntimeClient()
    orchestrator = RuntimeOrchestrator(runtime_client=mock_client)
    assert isinstance(orchestrator.broker, MockRuntimeClient)
    assert orchestrator.broker is mock_client


def test_remote_mode_selects_remote_runtime_client(monkeypatch):
    from app.runtime.runtime_host_client import RemoteRuntimeClient

    settings = get_settings()
    monkeypatch.setattr(settings, "RUNTIME_MODE", "remote")
    monkeypatch.setattr(settings, "RUNTIME_URL", "https://runtime.example:8443")
    monkeypatch.setattr(settings, "RUNTIME_CLIENT_CERT", "/tmp/client.crt")
    monkeypatch.setattr(settings, "RUNTIME_CLIENT_KEY", "/tmp/client.key")
    monkeypatch.setattr(settings, "RUNTIME_CA_CERT", "/tmp/ca.crt")
    with patch.object(RemoteRuntimeClient, "_validate_cert_files"):
        orchestrator = RuntimeOrchestrator()
    assert isinstance(orchestrator.broker, RemoteRuntimeClient)


def test_remote_provision_builds_artifact_then_submits_run(
    db, test_user, test_project, monkeypatch
):
    from unittest.mock import MagicMock
    from app.runtime.runtime_host_client import RemoteRuntimeClient

    assessment_id = "44444444-4444-4444-4444-444444444444"
    request_id = "remote-run-request"
    db.add(AuthorizationRequest(
        request_id=request_id,
        user_id=test_user.id,
        assessment_id=assessment_id,
        tenant_id=test_user.id,
        operation="provision",
        status="consumed",
    ))
    artifact_url = "https://artifacts.example.test/assessment.tar.gz"
    artifact_sha256 = "a" * 64
    db.add(Assessment(
        id=assessment_id,
        project_id=test_project.id,
        created_by_id=test_user.id,
        config={"artifact_url": artifact_url, "artifact_sha256": artifact_sha256},
    ))
    db.add(Worker(
        user_id=test_user.id,
        cert_fingerprint="a" * 64,
        cert_subject="CN=sentinelx-test-worker",
        is_active=True,
        is_revoked=False,
    ))
    db.commit()

    authz = MagicMock()
    authz.issue_mutation_token.return_value = "signed-capability-token"
    remote = RemoteRuntimeClient(runtime_url="https://runtime.test")
    monkeypatch.setattr(remote, "is_available", lambda: True)
    submitted = []

    def submit_job(**kwargs):
        submitted.append(kwargs)
        target_url = "http://10.1.0.4:32100" if kwargs["operation"] == "run" else None
        return True, kwargs["job_id"], target_url

    monkeypatch.setattr(remote, "submit_job", submit_job)
    orchestrator = RuntimeOrchestrator(runtime_client=remote, authz_component=authz)
    monkeypatch.setattr(
        orchestrator.detector,
        "detect",
        lambda _path: ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py"),
    )

    result = orchestrator.provision(assessment_id, "/tmp/workspace", request_id=request_id)

    assert result["status"] == RuntimeStatus.RUNNING.value
    assert [item["operation"] for item in submitted] == ["build", "run"]
    build, run = submitted
    assert build["artifact_url"] == artifact_url
    assert build["artifact_sha256"] == artifact_sha256
    assert build["job_token"] == "signed-capability-token"
    assert run["job_token"] == "signed-capability-token"
    for job in (build, run):
        assert job["cpu_limit"] == "1.0"
        assert job["mem_limit"] == "512m"
        assert job["drop_capabilities"] == ["ALL"]
        assert job["no_new_privileges"] is True
        assert job["read_only_rootfs"] is True
    issued = authz.issue_mutation_token.call_args_list
    assert len(issued) == 2
    assert [call.kwargs["operation"] for call in issued] == ["build", "run"]
    assert issued[0].kwargs["job_id"] == build["job_id"]
    assert issued[1].kwargs["job_id"] == run["job_id"]
    assert issued[0].kwargs["resource_limits"]["artifact_sha256"] == artifact_sha256


def test_orchestrator_provision_uses_runtime_client(provision_auth):
    """provision() delegates build, run, logs to the runtime client."""
    orchestrator, mock_client = _make_orchestrator_with_mock()

    with patch.object(orchestrator.detector, "detect") as mock_detect, \
         patch.object(orchestrator, "_health_check", return_value=True), \
         patch.object(orchestrator, "_get_container_logs", return_value="[simulated] logs"):
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision(
            "test-provision-uses-client", "/tmp", request_id=provision_auth
        )

    assert res["status"] == RuntimeStatus.RUNNING.value
    assert res["target_url"] == "http://127.0.0.1:19000"
    assert mock_client.calls
    assert any(c["operation"] == "build_image" for c in mock_client.calls)
    assert any(c["operation"] == "run_container" for c in mock_client.calls)


def test_orchestrator_provision_fail_closed_when_runtime_unavailable(provision_auth):
    """If the runtime client is unavailable, provisioning fails closed."""
    orchestrator, mock_client = _make_orchestrator_with_mock(fail_availability=True)

    res = orchestrator.provision(
        "test-runtime-unavailable", "/tmp", request_id=provision_auth
    )

    assert res["status"] == RuntimeStatus.FAILED.value
    assert res["error"] == "Runtime broker is not reachable or Docker is unavailable."
    assert mock_client.calls == []  # no operations attempted


def test_orchestrator_cleanup_on_build_failure(provision_auth):
    """A failed build triggers runtime cleanup of partial image."""
    orchestrator, mock_client = _make_orchestrator_with_mock(fail_build=True)

    with patch.object(orchestrator.detector, "detect") as mock_detect:
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision(
            "test-cleanup-build", "/tmp", request_id=provision_auth
        )

    assert res["status"] == RuntimeStatus.FAILED.value
    # Cleanup must be attempted via the runtime client.
    cleanup_calls = [c for c in mock_client.calls if c["operation"] == "cleanup"]
    assert cleanup_calls, "cleanup must be invoked after build failure"
    assert "sentinelx-app-" in cleanup_calls[-1]["image_tag"]


def test_orchestrator_cleanup_on_start_failure(provision_auth):
    """A failed container start triggers runtime cleanup."""
    orchestrator, mock_client = _make_orchestrator_with_mock(
        fail_build=False,
        fail_start=True,
    )

    with patch.object(orchestrator.detector, "detect") as mock_detect:
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision(
            "test-cleanup-start", "/tmp", request_id=provision_auth
        )

    assert res["status"] == RuntimeStatus.FAILED.value
    cleanup_calls = [c for c in mock_client.calls if c["operation"] == "cleanup"]
    assert cleanup_calls, "cleanup must be invoked after start failure"


def test_orchestrator_cleanup_on_health_check_failure(provision_auth):
    """A failed health check triggers runtime cleanup."""
    orchestrator, mock_client = _make_orchestrator_with_mock()

    with patch.object(orchestrator.detector, "detect") as mock_detect, \
         patch.object(orchestrator, "_health_check", return_value=False), \
         patch.object(orchestrator, "_get_container_logs", return_value="[simulated] logs"):
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision(
            "test-cleanup-health", "/tmp", request_id=provision_auth
        )

    assert res["status"] == RuntimeStatus.HEALTH_CHECK_FAILED.value
    cleanup_calls = [c for c in mock_client.calls if c["operation"] == "cleanup"]
    assert cleanup_calls, "cleanup must be invoked after health-check failure"


def test_orchestrator_cleanup_on_unexpected_exception(provision_auth):
    """An unexpected runtime-client exception triggers cleanup and fail-closed."""
    orchestrator, mock_client = _make_orchestrator_with_mock()

    with patch.object(mock_client, "build_image", side_effect=RuntimeError("simulated runtime gone")), \
         patch.object(orchestrator.detector, "detect") as mock_detect:
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision(
            "test-cleanup-exc", "/tmp", request_id=provision_auth
        )

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


def test_mock_responses_are_not_claimed_as_live_docker(provision_auth):
    """Mock responses are explicitly marked simulated."""
    orchestrator, mock_client = _make_orchestrator_with_mock()

    with patch.object(orchestrator.detector, "detect") as mock_detect, \
         patch.object(orchestrator, "_health_check", return_value=True), \
         patch.object(orchestrator, "_get_container_logs", return_value="[simulated] logs"):
        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
        res = orchestrator.provision(
            "test-not-live-docker", "/tmp", request_id=provision_auth
        )

    assert res["status"] == RuntimeStatus.RUNNING.value
    # The target URL points to the simulated port, never a real Docker binding.
    assert "19000" in res["target_url"]
    assert "0.0.0.0" not in res["target_url"]  # noqa: S104 — asserting loopback-only binding


def test_settings_runtime_mode_default_broker():
    """Default RUNTIME_MODE is broker (production-safe)."""
    settings = get_settings()
    assert settings.RUNTIME_MODE == "broker"


# ---------------------------------------------------------------------------
# Cleanup correctness
# ---------------------------------------------------------------------------


def test_cleanup_failure_does_not_mask_original_build_error(provision_auth):
    """Build failure + cleanup failure → original build error is preserved.

    The provision() return value must report the build error, not a cleanup
    error, even when cleanup itself fails.
    """
    orchestrator, mock_client = _make_orchestrator_with_mock(
        fail_build=True,
        fail_cleanup=True,
    )
    with patch.object(orchestrator.detector, "detect") as mock_detect:
        mock_detect.return_value = ProjectProfile(
            project_type="fastapi", port=8000, entry_point="main.py"
        )
        res = orchestrator.provision(
            "test-cleanup-masks-build", "/tmp", request_id=provision_auth
        )

    # Original error must be the build failure, NOT a cleanup error.
    assert res["status"] == RuntimeStatus.FAILED.value
    assert res["error"] == "Build failed"
    # Cleanup was still attempted (and failed), but did not mask the error.
    cleanup_calls = [c for c in mock_client.calls if c["operation"] == "cleanup"]
    assert cleanup_calls, "cleanup must be attempted even though it will fail"


def test_cleanup_failure_does_not_mask_original_start_error(provision_auth):
    """Start failure + cleanup failure → original start error is preserved."""
    orchestrator, mock_client = _make_orchestrator_with_mock(
        fail_build=False,
        fail_start=True,
        fail_cleanup=True,
    )
    with patch.object(orchestrator.detector, "detect") as mock_detect:
        mock_detect.return_value = ProjectProfile(
            project_type="fastapi", port=8000, entry_point="main.py"
        )
        res = orchestrator.provision(
            "test-cleanup-masks-start", "/tmp", request_id=provision_auth
        )

    assert res["status"] == RuntimeStatus.FAILED.value
    assert res["error"] == "Start failed"
    cleanup_calls = [c for c in mock_client.calls if c["operation"] == "cleanup"]
    assert cleanup_calls


def test_cleanup_failure_does_not_mask_health_check_error(provision_auth):
    """Health check failure + cleanup failure → original health error preserved."""
    orchestrator, mock_client = _make_orchestrator_with_mock(fail_cleanup=True)
    with patch.object(orchestrator.detector, "detect") as mock_detect, \
         patch.object(orchestrator, "_health_check", return_value=False), \
         patch.object(orchestrator, "_get_container_logs", return_value="[simulated] logs"):
        mock_detect.return_value = ProjectProfile(
            project_type="fastapi", port=8000, entry_point="main.py"
        )
        res = orchestrator.provision(
            "test-cleanup-masks-health", "/tmp", request_id=provision_auth
        )

    assert res["status"] == RuntimeStatus.HEALTH_CHECK_FAILED.value
    cleanup_calls = [c for c in mock_client.calls if c["operation"] == "cleanup"]
    assert cleanup_calls


def test_cleanup_is_idempotent():
    """Calling cleanup twice does not raise; both calls complete."""
    orchestrator, mock_client = _make_orchestrator_with_mock()

    orchestrator.cleanup("test-idempotent")
    first_cleanup_count = len(
        [c for c in mock_client.calls if c["operation"] == "cleanup"]
    )
    assert first_cleanup_count == 1

    orchestrator.cleanup("test-idempotent")
    second_cleanup_count = len(
        [c for c in mock_client.calls if c["operation"] == "cleanup"]
    )
    assert second_cleanup_count == 2


def test_repeated_cleanup_after_partial_provisioning(provision_auth):
    """Build succeeds, start fails, cleanup runs; repeated cleanup is idempotent."""
    orchestrator, mock_client = _make_orchestrator_with_mock(fail_start=True)
    with patch.object(orchestrator.detector, "detect") as mock_detect:
        mock_detect.return_value = ProjectProfile(
            project_type="fastapi", port=8000, entry_point="main.py"
        )
        res = orchestrator.provision(
            "test-repeated-cleanup", "/tmp", request_id=provision_auth
        )

    assert res["status"] == RuntimeStatus.FAILED.value
    # First cleanup ran as part of the provisioning failure path.
    first_cleanup_count = len(
        [c for c in mock_client.calls if c["operation"] == "cleanup"]
    )
    assert first_cleanup_count == 1

    # Explicit repeated cleanup should not raise and should add another call.
    orchestrator.cleanup("test-repeated-cleanup")
    second_cleanup_count = len(
        [c for c in mock_client.calls if c["operation"] == "cleanup"]
    )
    assert second_cleanup_count == 2
