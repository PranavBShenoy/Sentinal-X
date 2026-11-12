"""
Unit tests for Runtime Broker security policy.

Verifies the broker REJECTS dangerous configurations and enforces safe ones:
- Privileged containers rejected
- Host filesystem mounts rejected
- Host networking (network_mode=host) rejected
- Host PID namespace rejected
- Root user rejected
- Arbitrary capabilities rejected
- Docker exec not accepted
- Build network never 'host'
- Build context restricted to workspace base
- Image tag naming policy enforced
- Non-root, cap-drop=ALL, no-new-privileges, resource limits enforced
- 127.0.0.1-only port binding enforced
- --internal network enforced
"""

from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.runtime.broker.policy import (
    assert_no_dangerous_flags,
    build_docker_build_args,
    build_docker_run_args,
    validate_build_network_mode,
    validate_container_run_request,
    validate_image_tag,
    validate_resource_name,
    validate_workspace_path,
)
from app.runtime.broker.schemas import BrokerError

settings = get_settings()


# ---------------------------------------------------------------------------
# Resource naming
# ---------------------------------------------------------------------------

def test_validate_resource_name_accepts_valid():
    assert validate_resource_name("sentinelx-app-abc12345", "image_tag") == "sentinelx-app-abc12345"
    assert validate_resource_name("sentinelx-cont-abc12345", "container_name") == "sentinelx-cont-abc12345"
    assert validate_resource_name("sentinelx-net-abc12345", "network_name") == "sentinelx-net-abc12345"


def test_validate_resource_name_rejects_invalid():
    for bad in ["my-app", "sentinelx-app", "sentinelx-app-", "app-abc12345", "SentinelX-app-abc12345", ""]:
        with pytest.raises(BrokerError):
            validate_resource_name(bad, "resource")


# ---------------------------------------------------------------------------
# Image tag policy
# ---------------------------------------------------------------------------

def test_validate_image_tag_approved_prefix():
    assert validate_image_tag("sentinelx-app-abc12345") == "sentinelx-app-abc12345"


def test_validate_image_tag_unapproved_prefix_rejected():
    with pytest.raises(BrokerError):
        validate_image_tag("ubuntu:latest")
    with pytest.raises(BrokerError):
        validate_image_tag("python:3.11")  # not a sentinelx-app-* tag


# ---------------------------------------------------------------------------
# Workspace path policy
# ---------------------------------------------------------------------------

def test_validate_workspace_path_under_base():
    base = settings.ASSESSMENT_WORKSPACE_BASE.rstrip("/")
    assert validate_workspace_path(f"{base}/assessment-1") == f"{base}/assessment-1"


def test_validate_workspace_path_outside_base_rejected():
    with pytest.raises(BrokerError):
        validate_workspace_path("/etc")
    with pytest.raises(BrokerError):
        validate_workspace_path("/tmp/other")


# ---------------------------------------------------------------------------
# Build network mode
# ---------------------------------------------------------------------------

def test_validate_build_network_mode_rejects_host():
    with pytest.raises(BrokerError):
        validate_build_network_mode("host")
    with pytest.raises(BrokerError):
        validate_build_network_mode("default")
    assert validate_build_network_mode("none") == "none"
    assert validate_build_network_mode("internal") == "internal"


# ---------------------------------------------------------------------------
# Container run validation
# ---------------------------------------------------------------------------

def test_validate_container_run_request_valid():
    result = validate_container_run_request(
        container_name="sentinelx-cont-abc12345",
        image_tag="sentinelx-app-abc12345",
        network_name="sentinelx-net-abc12345",
        app_port=8000,
        host_port=12345,
    )
    assert result == ("sentinelx-cont-abc12345", "sentinelx-app-abc12345", "sentinelx-net-abc12345", 8000, 12345)


def test_validate_container_run_request_mismatched_assessment_rejected():
    with pytest.raises(BrokerError):
        validate_container_run_request(
            container_name="sentinelx-cont-aaa11111",
            image_tag="sentinelx-app-bbb22222",
            network_name="sentinelx-net-ccc33333",
            app_port=8000,
            host_port=12345,
        )


def test_validate_container_run_request_invalid_port_rejected():
    with pytest.raises(BrokerError):
        validate_container_run_request(
            container_name="sentinelx-cont-abc12345",
            image_tag="sentinelx-app-abc12345",
            network_name="sentinelx-net-abc12345",
            app_port=80,  # below 1024
            host_port=12345,
        )


# ---------------------------------------------------------------------------
# Docker run args: broker enforces safe params, caller cannot weaken
# ---------------------------------------------------------------------------

def test_build_docker_run_args_enforces_isolation():
    args = build_docker_run_args(
        container_name="sentinelx-cont-abc12345",
        image_tag="sentinelx-app-abc12345",
        network_name="sentinelx-net-abc12345",
        app_port=8000,
        host_port=12345,
    )
    arg_str = " ".join(args)
    # Mandatory safe controls
    assert "--cap-drop=ALL" in arg_str
    assert "--security-opt=no-new-privileges:true" in arg_str
    assert "--read-only" in arg_str
    assert "--tmpfs=/tmp:rw,noexec,nosuid,size=64m" in arg_str
    assert "--memory=512m" in arg_str
    assert "--cpus=1.0" in arg_str
    assert "--pids-limit=100" in arg_str
    assert "--user=appuser" in arg_str  # non-root
    assert "-p=127.0.0.1:12345:8000" in arg_str  # loopback-only binding
    assert "--network=sentinelx-net-abc12345" in arg_str  # internal network
    # Dangerous flags MUST NOT be present
    assert "--privileged" not in arg_str
    assert "--network=host" not in arg_str
    assert "--pid=host" not in arg_str
    assert "--user=root" not in arg_str
    assert "-v " not in arg_str and "--volume" not in arg_str
    assert "--cap-add" not in arg_str


# ---------------------------------------------------------------------------
# Docker build args: never --network=host
# ---------------------------------------------------------------------------

def test_build_docker_build_args_never_host_network():
    args = build_docker_build_args("/tmp/sentinelx/workspaces/assessment-1", "sentinelx-app-abc12345")
    arg_str = " ".join(args)
    assert "--network=host" not in arg_str
    assert "/tmp/sentinelx/workspaces/assessment-1" in arg_str
    assert "-t" in arg_str and "sentinelx-app-abc12345" in arg_str


# ---------------------------------------------------------------------------
# Dangerous flags rejection
# ---------------------------------------------------------------------------

def test_assert_no_dangerous_flags_rejects_all():
    dangerous_sets = [
        {"privileged": True},
        {"cap_add": ["SYS_ADMIN"]},
        {"volumes": ["/host:/host"]},
        {"network_mode": "host"},
        {"pid_mode": "host"},
        {"user": "root"},
        {"exec": "sh"},
        {"command": "/bin/sh"},
    ]
    for flags in dangerous_sets:
        with pytest.raises(BrokerError):
            assert_no_dangerous_flags(flags)


def test_assert_no_dangerous_flags_allows_empty():
    assert_no_dangerous_flags(None)
    assert_no_dangerous_flags({})
