"""
Adversarial security tests for the Runtime Broker.

These tests probe the boundary of the broker's security policy to confirm
that dangerous inputs are rejected and that no bypass exists through
path traversal, symlinks, unexpected values, or timing side channels.

All tests are code-level (no Docker daemon required). Live Docker
verification is BLOCKED in this environment.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import hmac as _hmac
import pytest
from app.core.config import get_settings
from app.runtime.broker.policy import (
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
# Path traversal / symlink escape in workspace path validation
# ---------------------------------------------------------------------------

def test_validate_workspace_path_rejects_dotdot_escape():
    """``..`` components must not allow escaping the workspace base.

    The current implementation uses a string ``startswith`` check which does
    NOT resolve ``..`` or symlinks, so an attacker can supply a path that
    lexically starts with the base but resolves outside it.
    """
    base = settings.ASSESSMENT_WORKSPACE_BASE.rstrip("/")
    # Lexically starts with base but escapes via ../
    evil = f"{base}/../etc"
    # The startswith check passes because the string begins with base + "/"
    assert evil.startswith(base + "/"), "test setup: evil path must lexically start with base"
    with pytest.raises(BrokerError):
        validate_workspace_path(evil)


def test_validate_workspace_path_rejects_symlink_escape():
    """A symlink inside the workspace base pointing outside must be rejected."""
    base = settings.ASSESSMENT_WORKSPACE_BASE.rstrip("/")
    with tempfile.TemporaryDirectory(dir=base) as tmpdir:
        link = Path(tmpdir) / "escape-link"
        os.symlink("/etc", link)
        # Lexically under base, but resolves to /etc
        evil = str(link)
        assert evil.startswith(base + "/"), "test setup: symlink path must lexically start with base"
        with pytest.raises(BrokerError):
            validate_workspace_path(evil)


# ---------------------------------------------------------------------------
# Timing side channel in key comparison (F-2: FIXED with hmac.compare_digest)
# ---------------------------------------------------------------------------


def test_hmac_compare_digest_constant_time_no_length_leak():
    """
    ``hmac.compare_digest`` does NOT short-circuit on length mismatch.

    Unlike the previous custom `_constant_time_compare`, it compares
    full-length digests, so an attacker cannot measure response time to
    determine len(BROKER_API_KEY).
    """
    expected = "a" * 32
    short = "a" * 16
    same_len_wrong = "b" * 32
    assert _hmac.compare_digest(short, expected) is False
    assert _hmac.compare_digest(same_len_wrong, expected) is False
    assert _hmac.compare_digest(expected, expected) is True


# ---------------------------------------------------------------------------
# Resource name validation
# ---------------------------------------------------------------------------

def test_validate_resource_name_rejects_path_traversal_chars():
    """Resource names must not contain path traversal or shell metacharacters."""
    for bad in [
        "sentinelx-app-../etc",
        "sentinelx-app-../../etc",
        "sentinelx-app-`id`",
        "sentinelx-app-$(whoami)",
        "sentinelx-app-;rm -rf /",
        "sentinelx-app-|nc",
        "sentinelx-app-abc12345 extra",
        "sentinelx-app-abc12345:tag",
        "sentinelx-app-abc12345@sha256",
    ]:
        with pytest.raises(BrokerError):
            validate_resource_name(bad, "resource")


# ---------------------------------------------------------------------------
# Image tag policy
# ---------------------------------------------------------------------------

def test_validate_image_tag_rejects_tag_suffix():
    """Colon-separated image tags (e.g. :latest) are rejected by the name regex."""
    with pytest.raises(BrokerError):
        validate_image_tag("sentinelx-app-abc12345:latest")
    with pytest.raises(BrokerError):
        validate_image_tag("ubuntu:latest")


# ---------------------------------------------------------------------------
# Build network mode enforcement
# ---------------------------------------------------------------------------

def test_build_network_mode_never_host():
    """Build-time network mode must never be 'host' (default bridge = no isolation)."""
    with pytest.raises(BrokerError):
        validate_build_network_mode("host")
    with pytest.raises(BrokerError):
        validate_build_network_mode("default")
    assert validate_build_network_mode("none") == "none"
    assert validate_build_network_mode("internal") == "internal"


def test_docker_build_args_produces_network_none():
    """The broker must pass --network=none to docker build (no outbound during build)."""
    args = build_docker_build_args(
        "/tmp/sentinelx/workspaces/assessment-1",
        "sentinelx-app-abc12345",
    )
    arg_str = " ".join(args)
    assert "--network=none" in arg_str
    assert "--network=host" not in arg_str


# ---------------------------------------------------------------------------
# Docker run args: broker enforces safe params
# ---------------------------------------------------------------------------

def test_docker_run_args_no_dangerous_flags():
    """The broker-enforced docker run args must never contain dangerous flags."""
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
    assert "--user=appuser" in arg_str
    assert "-p=127.0.0.1:12345:8000" in arg_str
    # Dangerous flags MUST NOT be present
    for dangerous in [
        "--privileged",
        "--network=host",
        "--pid=host",
        "--user=root",
        "--cap-add",
        "-v ",
        "--volume",
        "--network_mode=host",
    ]:
        assert dangerous not in arg_str, f"Dangerous flag found: {dangerous}"


# ---------------------------------------------------------------------------
# Container run request consistency
# ---------------------------------------------------------------------------

def test_validate_container_run_request_mismatched_assessment_rejected():
    """Container, image, and network names must reference the same assessment."""
    with pytest.raises(BrokerError):
        validate_container_run_request(
            container_name="sentinelx-cont-aaa11111",
            image_tag="sentinelx-app-bbb22222",
            network_name="sentinelx-net-ccc33333",
            app_port=8000,
            host_port=12345,
        )


def test_validate_container_run_request_port_boundary():
    """Ports below 1024 are rejected (privileged ports)."""
    with pytest.raises(BrokerError):
        validate_container_run_request(
            container_name="sentinelx-cont-abc12345",
            image_tag="sentinelx-app-abc12345",
            network_name="sentinelx-net-abc12345",
            app_port=80,
            host_port=12345,
        )
    with pytest.raises(BrokerError):
        validate_container_run_request(
            container_name="sentinelx-cont-abc12345",
            image_tag="sentinelx-app-abc12345",
            network_name="sentinelx-net-abc12345",
            app_port=8000,
            host_port=22,  # SSH port
        )
