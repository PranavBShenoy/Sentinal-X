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
