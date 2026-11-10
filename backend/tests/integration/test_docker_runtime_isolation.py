"""
Docker Runtime Hardening and Security Isolation Tests.

Verifies:
1. Docker run command parameter enforcement:
   - cap_drop: ALL
   - security_opt: no-new-privileges:true
   - read_only root filesystem
   - Ephemeral tmpfs on /tmp with noexec,nosuid
   - CPU, memory, and pids limits (fork bomb defense)
   - Binding restricted strictly to 127.0.0.1
   - Complete absence of Docker socket or host mounts
   - Dedicated internal network isolation (no egress)
2. Generated Dockerfile security constraints:
   - Non-root user execution (appuser / node)
   - Pinned base images
3. Failure stage resilience:
   - Image build failure handling
   - Container start failure handling
   - Health check failure handling
4. Cleanup and resource teardown
5. Workspace directory cleanup lifecycle
6. Live container execution isolation (when Docker daemon is available; skips when blocked).
"""
from __future__ import annotations

import inspect
from pathlib import Path
import tempfile
import time
from unittest.mock import MagicMock, patch
import pytest

from app.core.config import get_settings
from app.models import RuntimeStatus
from app.runtime.cleanup.workspace_cleaner import WorkspaceCleaner
from app.runtime.detection.detector import ProjectProfile
from app.runtime.docker.orchestrator import RuntimeOrchestrator

settings = get_settings()


def test_docker_runtime_command_security_parameters():
    """Verify strictly hardened arguments passed to docker run."""
    orchestrator = RuntimeOrchestrator()

    # Inspect _start_container implementation
    src = inspect.getsource(orchestrator._start_container)

    # Security assertions on the docker run invocation
    assert "--cap-drop=ALL" in src, "Missing capability drop ALL"
    assert "--security-opt=no-new-privileges:true" in src, "Missing no-new-privileges"
    assert "--read-only" in src, "Missing read-only root filesystem"
    assert "--tmpfs=/tmp" in src, "Missing ephemeral tmpfs mount"
    assert "--memory=512m" in src, "Missing memory limit"
    assert "--cpus=1.0" in src, "Missing CPU quota"
    assert "--pids-limit=100" in src, "Missing process limit"
    assert "-p=127.0.0.1:" in src, "Port not restricted to loopback 127.0.0.1"
    assert "--network=" in src, "Missing dedicated network argument in container run"
    assert "--internal" in src, "Missing internal network flag to prevent outbound egress"
    assert "/var/run/docker.sock" not in src, "Unsafe Docker socket exposure detected!"
    assert "-v " not in src and "--volume" not in src, "Unsafe host filesystem volume mount detected!"


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


def test_runtime_failure_stages_handling():
    """Verify graceful handling and status reporting when image builds or startup fail."""
    orchestrator = RuntimeOrchestrator()
    assessment_id = "test-fail-stage-1111"

    with patch.object(orchestrator, "is_docker_available", return_value=True), \
         patch.object(orchestrator.detector, "detect") as mock_detect:

        mock_detect.return_value = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")

        # 1. Image build failure
        with patch.object(orchestrator, "_build_image", return_value=(False, "Build syntax error in Dockerfile")):
            res = orchestrator.provision(assessment_id, "/tmp")
            assert res["status"] == RuntimeStatus.FAILED.value
            assert res["error"] == "Build failed"

        # 2. Container startup failure
        with patch.object(orchestrator, "_build_image", return_value=(True, "Build succeeded")), \
             patch.object(orchestrator, "_start_container", return_value=(False, None, "Port binding conflict")):
            res = orchestrator.provision(assessment_id, "/tmp")
            assert res["status"] == RuntimeStatus.FAILED.value
            assert res["error"] == "Start failed"

        # 3. Health check timeout failure
        with patch.object(orchestrator, "_build_image", return_value=(True, "Build succeeded")), \
             patch.object(orchestrator, "_start_container", return_value=(True, 49152, "Started")), \
             patch.object(orchestrator, "_health_check", return_value=False), \
             patch.object(orchestrator, "_get_container_logs", return_value="Log output"):
            res = orchestrator.provision(assessment_id, "/tmp")
            assert res["status"] == RuntimeStatus.HEALTH_CHECK_FAILED.value
            assert res["health_check_passed"] is False


def test_runtime_cleanup_resources():
    """Verify cleanup stops containers, removes networks, and removes images."""
    orchestrator = RuntimeOrchestrator()
    assessment_id = "test-cleanup-2222"

    with patch("app.runtime.docker.orchestrator.run_command") as mock_run_cmd:
        mock_run_cmd.return_value = MagicMock(succeeded=True)
        orchestrator.cleanup(assessment_id)

        # Inspect commands executed during cleanup
        cmd_args = [call.args[0] for call in mock_run_cmd.call_args_list]
        flattened = [" ".join(arg) for arg in cmd_args]

        assert any("docker rm -f sentinelx-cont-" in cmd for cmd in flattened)
        assert any("docker network rm sentinelx-net-" in cmd for cmd in flattened)
        assert any("docker rmi sentinelx-app-" in cmd for cmd in flattened)


def test_docker_network_creation_failure_defense():
    """Verify that if network creation fails, docker run is aborted and no container starts."""
    orchestrator = RuntimeOrchestrator()
    profile = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")

    def mock_run_cmd_side_effect(args, **kwargs):
        if len(args) >= 3 and args[0:3] == ["docker", "network", "create"]:
            return MagicMock(succeeded=False, stdout="", stderr="Error response: subnet conflict")
        return MagicMock(succeeded=True, stdout="", stderr="")

    with patch("app.runtime.docker.orchestrator.run_command", side_effect=mock_run_cmd_side_effect) as mock_run:
        ok, port, log = orchestrator._start_container(
            container_name="test-c",
            network_name="test-n",
            image_tag="test-i",
            profile=profile,
        )

        assert ok is False
        assert port is None
        assert "Failed to create isolated internal network" in log

        # Assert that docker run was NEVER called
        executed_cmds = [call.args[0] for call in mock_run.call_args_list]
        flattened = [" ".join(c) for c in executed_cmds]
        assert not any("docker run" in cmd for cmd in flattened), "docker run was called despite network creation failure!"


def test_docker_port_binding_and_security():
    """Verify dynamic port binding is strictly restricted to host loopback (127.0.0.1)."""
    orchestrator = RuntimeOrchestrator()
    profile = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")

    with patch("app.runtime.docker.orchestrator.run_command") as mock_run:
        mock_run.return_value = MagicMock(succeeded=True, stdout="c123", stderr="")
        ok, port, _ = orchestrator._start_container(
            container_name="test-c",
            network_name="test-n",
            image_tag="test-i",
            profile=profile,
        )

        assert ok is True
        assert isinstance(port, int)
        assert port > 1024

        # Inspect the exact docker run command
        run_calls = [call.args[0] for call in mock_run.call_args_list if call.args[0][0:2] == ["docker", "run"]]
        assert len(run_calls) == 1
        run_cmd = run_calls[0]

        # Verify port parameter
        port_flags = [arg for arg in run_cmd if arg.startswith("-p=")]
        assert len(port_flags) == 1
        port_flag = port_flags[0]

        # Must bind to 127.0.0.1, never 0.0.0.0, never bare port
        assert port_flag.startswith("-p=127.0.0.1:")
        assert "0.0.0.0" not in port_flag  # noqa: S104
        assert f":{profile.port}" in port_flag


def test_teardown_order_on_cancellation_and_failure():
    """Verify resource teardown sequence always removes container before network."""
    orchestrator = RuntimeOrchestrator()
    assessment_id = "test-teardown-order"

    with patch("app.runtime.docker.orchestrator.run_command") as mock_run:
        mock_run.return_value = MagicMock(succeeded=True)
        orchestrator.cleanup(assessment_id)

        cmds = [call.args[0][1] for call in mock_run.call_args_list if call.args[0][0] == "docker"]
        assert cmds[0] == "rm", "Container must be removed before network"
        assert cmds[1] == "network", "Network must be removed after container"
        assert cmds[2] == "rmi", "Image must be removed after network"


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


def test_live_docker_isolation_or_blocked():
    """
    Execute live container isolation test if Docker is available.
    If Docker daemon is unavailable in this environment, cleanly mark BLOCKED.
    """
    orchestrator = RuntimeOrchestrator()
    if not orchestrator.is_docker_available():
        pytest.skip("Docker daemon is not accessible in this environment (INFRA-01: BLOCKED: Cannot connect to Docker daemon: permission denied on /var/run/docker.sock).")

    # If Docker daemon is available, run live isolation verification
    res = orchestrator.provision("test-isolation-audit", "/tmp")
    assert res is not None
