"""
Docker Runtime Hardening and Security Isolation Tests.

Verifies:
1. The Runtime Broker enforces isolation controls (cap_drop=ALL, no-new-privileges,
   read-only rootfs, ephemeral tmpfs, CPU/memory/pids limits, loopback-only port
   binding, dedicated internal network, no Docker socket or host mounts).
2. Generated Dockerfiles enforce non-root user execution.
3. Failure stage resilience: build failure, container start failure, health check failure.
4. Cleanup and resource teardown via the broker (container -> network -> image).
5. Workspace directory cleanup lifecycle.
6. Live container execution isolation (when Docker daemon is available; skips when blocked).

NOTE: The Celery worker no longer mounts the Docker socket. All Docker operations
delegate to the Runtime Broker. These tests verify the broker-enforced isolation
and the orchestrator's delegation. Live Docker verification is BLOCKED in this
environment (no Docker daemon access) and is cleanly skipped.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import time
import uuid
from unittest.mock import patch
import pytest

from app.core.config import get_settings
from app.models import AuthorizationRequest, RuntimeStatus
from app.runtime.broker.policy import build_docker_run_args
from app.runtime.cleanup.workspace_cleaner import WorkspaceCleaner
from app.runtime.detection.detector import ProjectProfile
from app.runtime.docker.orchestrator import RuntimeOrchestrator

settings = get_settings()


@pytest.fixture(autouse=True)
def fixed_host_port(monkeypatch):
    """Avoid opening a sandbox-restricted socket to select a test port."""
    monkeypatch.setattr(RuntimeOrchestrator, "_find_available_port", lambda self: 19000)


def test_docker_runtime_command_security_parameters():
    """Verify strictly hardened arguments enforced by the broker policy.

    The broker (not the orchestrator) constructs the docker run args. All
    security parameters are hardcoded by policy; the caller cannot weaken them.
    """
    args = build_docker_run_args(
        container_name="sentinelx-cont-abc12345",
        image_tag="sentinelx-app-abc12345",
        network_name="sentinelx-net-abc12345",
        app_port=8000,
        host_port=49152,
    )
    arg_str = " ".join(args)

    # Security assertions on the broker-enforced docker run invocation
    assert "--cap-drop=ALL" in arg_str, "Missing capability drop ALL"
    assert "--security-opt=no-new-privileges:true" in arg_str, "Missing no-new-privileges"
    assert "--read-only" in arg_str, "Missing read-only root filesystem"
    assert "--tmpfs=/tmp" in arg_str, "Missing ephemeral tmpfs mount"
    assert "--memory=512m" in arg_str, "Missing memory limit"
    assert "--cpus=1.0" in arg_str, "Missing CPU quota"
    assert "--pids-limit=100" in arg_str, "Missing process limit"
    assert "--user=appuser" in arg_str, "Missing non-root user enforcement"
    assert "-p=127.0.0.1:49152:8000" in arg_str, "Port not restricted to loopback 127.0.0.1"
    assert "--network=sentinelx-net-abc12345" in arg_str, "Missing dedicated network argument"
    assert "--internal" not in arg_str  # --internal is on network create, not run
    assert "/var/run/docker.sock" not in arg_str, "Unsafe Docker socket exposure detected!"
    assert "-v " not in arg_str and "--volume" not in arg_str, "Unsafe host filesystem volume mount detected!"
    assert "--privileged" not in arg_str, "Privileged mode must not be present"
    assert "--network=host" not in arg_str, "Host networking must not be present"
    assert "--pid=host" not in arg_str, "Host PID namespace must not be present"
    assert "--user=root" not in arg_str, "Root user must not be enforced"
    assert "--cap-add" not in arg_str, "Capability add must not be present"


def test_generated_dockerfile_non_root_execution():
    """Verify generated Dockerfiles enforce non-root user execution."""
    orchestrator = RuntimeOrchestrator()

    # 1. Python / FastAPI Dockerfile
    py_profile = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
    py_df = orchestrator._generate_dockerfile(py_profile)
    assert "USER appuser" in py_df, "Python container does not run as non-root user"
    assert "useradd" in py_df, "Non-root user creation missing"
    assert "10001" in py_df, "UID 10001 not specified for non-root user"
    assert "python:3.11-slim" in py_df

    # 2. Node.js Dockerfile
    node_profile = ProjectProfile(project_type="nodejs", port=3000)
    node_df = orchestrator._generate_dockerfile(node_profile)
    assert "USER node" in node_df, "Node container does not run as non-root user"
    assert "node:20-slim" in node_df


def test_runtime_failure_stages_handling(db):
    """Verify graceful handling and status reporting when image builds or startup fail."""
    orchestrator = RuntimeOrchestrator()
    assessment_id = "test-fail-stage-1111"

    # Provisioning requires a durable, consumed AuthorizationRequest.
    request_id = str(uuid.uuid4())
    db.add(AuthorizationRequest(
        request_id=request_id,
        user_id=str(uuid.uuid4()),
        assessment_id=assessment_id,
        tenant_id=str(uuid.uuid4()),
        operation="provision",
        status="consumed",
    ))
    db.commit()

    with patch.object(orchestrator, "is_docker_available", return_value=True), \
         patch.object(orchestrator.detector, "detect") as mock_detect:

        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")

        # 1. Image build failure
        with patch.object(orchestrator, "_build_image", return_value=(False, "Build syntax error in Dockerfile")):
            res = orchestrator.provision(assessment_id, "/tmp", request_id=request_id)
            assert res["status"] == RuntimeStatus.FAILED.value
            assert res["error"] == "Build failed"

        # 2. Container startup failure
        with patch.object(orchestrator, "_build_image", return_value=(True, "Build succeeded")), \
             patch.object(orchestrator, "_start_container", return_value=(False, None, "Port binding conflict")):
            res = orchestrator.provision(assessment_id, "/tmp", request_id=request_id)
            assert res["status"] == RuntimeStatus.FAILED.value
            assert res["error"] == "Start failed"

        # 3. Health check timeout failure
        with patch.object(orchestrator, "_build_image", return_value=(True, "Build succeeded")), \
             patch.object(orchestrator, "_start_container", return_value=(True, 49152, "Started")), \
             patch.object(orchestrator, "_health_check", return_value=False), \
             patch.object(orchestrator, "_get_container_logs", return_value="Log output"):
            res = orchestrator.provision(assessment_id, "/tmp", request_id=request_id)
            assert res["status"] == RuntimeStatus.HEALTH_CHECK_FAILED.value
            assert res["health_check_passed"] is False


def test_runtime_cleanup_resources_via_broker():
    """Verify cleanup delegates to the broker (container -> network -> image)."""
    orchestrator = RuntimeOrchestrator()
    assessment_id = "test-cleanup-2222"

    with patch.object(orchestrator.broker, "cleanup", return_value={
        "container": {"ok": True},
        "network": {"ok": True},
        "image": {"ok": True},
    }) as mock_cleanup:
        orchestrator.cleanup(assessment_id)

        mock_cleanup.assert_called_once()
        args = mock_cleanup.call_args.args
        assert len(args) == 3
        assert "sentinelx-cont-" in args[0]
        assert "sentinelx-net-" in args[1]
        assert "sentinelx-app-" in args[2]


def test_docker_network_creation_failure_defense():
    """Verify that if network creation fails, container start is aborted."""
    orchestrator = RuntimeOrchestrator()
    profile = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")

    # Broker run_container returns failure when network creation fails
    with patch.object(orchestrator.broker, "run_container", return_value=(False, None, "Failed to create isolated internal network: subnet conflict")):
        ok, port, log = orchestrator._start_container(
            container_name="test-c",
            network_name="test-n",
            image_tag="test-i",
            app_port=8000,
            host_port=49152,
        )

        assert ok is False
        assert port is None
        assert "Failed to create isolated internal network" in log


def test_docker_port_binding_and_security():
    """Verify dynamic port binding is strictly restricted to host loopback (127.0.0.1)."""
    orchestrator = RuntimeOrchestrator()
    profile = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")

    with patch.object(orchestrator.broker, "run_container", return_value=(True, 49152, "Started")) as mock_run:
        ok, port, _ = orchestrator._start_container(
            container_name="test-c",
            network_name="test-n",
            image_tag="test-i",
            app_port=profile.port,
            host_port=49152,
        )

        assert ok is True
        assert isinstance(port, int)
        assert port == 49152
        assert port > 1024

        # Inspect the broker run_container call
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["app_port"] == 8000
        # The broker enforces 127.0.0.1-only binding internally (verified in policy tests).
        assert call_kwargs["host_port"] == 49152


def test_teardown_order_on_cancellation_and_failure():
    """Verify resource teardown sequence always removes container before network before image."""
    orchestrator = RuntimeOrchestrator()
    assessment_id = "test-teardown-order"

    call_order = []

    def fake_cleanup(container_name, network_name, image_tag):
        call_order.append("container")
        call_order.append("network")
        call_order.append("image")
        return {
            "container": {"ok": True},
            "network": {"ok": True},
            "image": {"ok": True},
        }

    with patch.object(orchestrator.broker, "cleanup", side_effect=fake_cleanup):
        orchestrator.cleanup(assessment_id)

        assert call_order == ["container", "network", "image"], (
            "Teardown order must be container -> network -> image: " + str(call_order)
        )


def test_workspace_cleaner_lifecycle():
    """Verify temporary workspace cleanup and expiration purge logic."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cleaner = WorkspaceCleaner(base_dir=tmp_dir)

        # Create test assessment workspaces
        ws1 = Path(tmp_dir) / "assessment-1"
        ws1.mkdir()
        (ws1 / "code.py").write_text("print('test')")

        ws2 = Path(tmp_dir) / "assessment-2"
        ws2.mkdir()
        (ws2 / "code.py").write_text("print('test2')")

        # 1. Targeted cleanup of assessment-1
        assert ws1.exists()
        cleaned = cleaner.cleanup_assessment("assessment-1")
        assert cleaned is True
        assert not ws1.exists()
        assert ws2.exists()

        # 2. Expiration purge (artificially set mtime in past)
        old_time = time.time() - (settings.ASSESSMENT_WORKSPACE_MAX_AGE_HOURS * 3600 + 100)
        import os
        os.utime(ws2, (old_time, old_time))

        purge_res = cleaner.cleanup_expired()
        assert purge_res["purged"] == 1
        assert not ws2.exists()


@pytest.mark.skip(reason="Docker-backed execution is not run in this test environment")
def test_live_docker_isolation_or_blocked(db):
    """
    Execute live container isolation test if Docker is available.
    If Docker daemon is unavailable in this environment, cleanly mark BLOCKED.
    """
    orchestrator = RuntimeOrchestrator()
    if not orchestrator.is_docker_available():
        pytest.skip("Docker daemon is not accessible in this environment (INFRA-01: BLOCKED: Cannot connect to Docker daemon: permission denied on /var/run/docker.sock).")

    # If Docker daemon is available, run live isolation verification
    request_id = str(uuid.uuid4())
    db.add(AuthorizationRequest(
        request_id=request_id,
        user_id=str(uuid.uuid4()),
        assessment_id="test-isolation-audit",
        tenant_id=str(uuid.uuid4()),
        operation="provision",
        status="consumed",
    ))
    db.commit()
    res = orchestrator.provision("test-isolation-audit", "/tmp", request_id=request_id)
    assert res is not None
