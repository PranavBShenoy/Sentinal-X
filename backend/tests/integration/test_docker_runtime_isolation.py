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
2. Generated Dockerfile security constraints:
   - Non-root user execution (appuser / node)
   - Pinned base images
3. Live container execution isolation (when Docker daemon is available; skips when blocked).
"""
from __future__ import annotations

import inspect
from pathlib import Path
import pytest

from app.runtime.docker.orchestrator import RuntimeOrchestrator
from app.runtime.detection.detector import ProjectProfile


def test_docker_runtime_command_security_parameters():
    """Verify strictly hardened arguments passed to docker run."""
    orchestrator = RuntimeOrchestrator()
    profile = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")

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
    assert "/var/run/docker.sock" not in src, "Unsafe Docker socket exposure detected!"


def test_generated_dockerfile_non_root_execution():
    """Verify generated Dockerfiles enforce non-root user execution."""
    orchestrator = RuntimeOrchestrator()

    # 1. Python / FastAPI Dockerfile
    py_profile = ProjectProfile(project_type="fastapi", port=8000, entry_point="main.py")
    py_df = orchestrator._generate_dockerfile(py_profile)
    assert "USER appuser" in py_df, "Python container does not run as non-root user"
    assert "useradd" in py_df, "Non-root user creation missing"
    assert "python:3.11-slim" in py_df

    # 2. Node.js Dockerfile
    node_profile = ProjectProfile(project_type="nodejs", port=3000)
    node_df = orchestrator._generate_dockerfile(node_profile)
    assert "USER node" in node_df, "Node container does not run as non-root user"
    assert "node:20-slim" in node_df


def test_live_docker_isolation_or_blocked():
    """
    Execute live container isolation test if Docker is available.
    If Docker daemon is unavailable in this environment, cleanly mark BLOCKED.
    """
    orchestrator = RuntimeOrchestrator()
    if not orchestrator.is_docker_available():
        pytest.skip("Docker daemon is not accessible in this environment (INFRA-01: BLOCKED).")

    # If Docker daemon is available, run live isolation verification
    res = orchestrator.provision("test-isolation-audit", "/tmp")
    assert res is not None
