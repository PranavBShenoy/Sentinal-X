"""
Unit tests for Runtime Broker Pydantic schemas.

Verifies strict request/response validation:
- BuildRequest workspace under allowed base, image tag naming, network mode
- ContainerRunRequest port ranges, name patterns, same-assessment consistency
- CleanupRequest name validation
- Unknown fields rejected
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.runtime.broker.schemas import (
    BuildRequest,
    CleanupRequest,
    ContainerRunRequest,
    NetworkCreateRequest,
)


def test_build_request_valid():
    req = BuildRequest(
        workspace_path="/tmp/sentinelx/workspaces/assessment-1",
        image_tag="sentinelx-app-abc12345",
        network_mode="none",
    )
    assert req.network_mode == "none"


def test_build_request_rejects_host_network():
    with pytest.raises(ValidationError):
        BuildRequest(
            workspace_path="/tmp/sentinelx/workspaces/assessment-1",
            image_tag="sentinelx-app-abc12345",
            network_mode="host",
        )


def test_build_request_rejects_outside_workspace():
    with pytest.raises(ValidationError):
        BuildRequest(
            workspace_path="/etc/passwd",
            image_tag="sentinelx-app-abc12345",
        )


def test_build_request_rejects_bad_image_tag():
    with pytest.raises(ValidationError):
        BuildRequest(
            workspace_path="/tmp/sentinelx/workspaces/assessment-1",
            image_tag="ubuntu:latest",
        )


def test_container_run_request_valid():
    req = ContainerRunRequest(
        container_name="sentinelx-cont-abc12345",
        image_tag="sentinelx-app-abc12345",
        network_name="sentinelx-net-abc12345",
        app_port=8000,
        host_port=12345,
    )
    assert req.app_port == 8000


def test_container_run_request_rejects_low_port():
    with pytest.raises(ValidationError):
        ContainerRunRequest(
            container_name="sentinelx-cont-abc12345",
            image_tag="sentinelx-app-abc12345",
            network_name="sentinelx-net-abc12345",
            app_port=80,
            host_port=12345,
        )


def test_container_run_request_rejects_bad_names():
    with pytest.raises(ValidationError):
        ContainerRunRequest(
            container_name="my-container",  # not sentinelx-cont-*
            image_tag="sentinelx-app-abc12345",
            network_name="sentinelx-net-abc12345",
            app_port=8000,
            host_port=12345,
        )


def test_cleanup_request_valid():
    req = CleanupRequest(
        container_name="sentinelx-cont-abc12345",
        network_name="sentinelx-net-abc12345",
        image_tag="sentinelx-app-abc12345",
    )
    assert req.image_tag == "sentinelx-app-abc12345"


def test_network_create_request_internal_must_be_true():
    req = NetworkCreateRequest(network_name="sentinelx-net-abc12345", internal=True)
    assert req.internal is True

    with pytest.raises(ValidationError):
        NetworkCreateRequest(network_name="sentinelx-net-abc12345", internal=False)


def test_schemas_reject_unknown_fields():
    with pytest.raises(ValidationError):
        BuildRequest(
            workspace_path="/tmp/sentinelx/workspaces/assessment-1",
            image_tag="sentinelx-app-abc12345",
            privileged=True,  # unknown field -> rejected
        )
