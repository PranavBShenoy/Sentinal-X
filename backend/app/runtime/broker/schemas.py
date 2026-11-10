"""
Strict Pydantic schemas for broker requests/responses.

The broker accepts only minimal, validated operational parameters. All
security-relevant Docker parameters are decided by the broker policy and are
NOT accepted from the caller. Unknown fields are rejected.
"""

from __future__ import annotations

import re
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.config import get_settings

settings = get_settings()

# Naming patterns enforced for all Docker resources managed by the broker.
_RESOURCE_NAME_RE = re.compile(r"^sentinelx-(app|cont|net)-[a-z0-9]{1,12}$")
_ASSESSMENT_ID_RE = re.compile(r"^[0-9a-f]{8,}$")


def _is_valid_resource_name(name: str) -> bool:
    return bool(_RESOURCE_NAME_RE.match(name or ""))


def _is_valid_assessment_id(assessment_id: str) -> bool:
    return bool(_ASSESSMENT_ID_RE.match(assessment_id or ""))


class BrokerError(Exception):
    """Raised when a broker policy violation or execution error occurs."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class BrokerResponse(BaseModel):
    """Standardized broker response."""

    ok: bool
    status: str
    message: str
    data: Optional[dict] = None


class BuildRequest(BaseModel):
    """Request to build an assessment image.

    workspace_path must be under ASSESSMENT_WORKSPACE_BASE.
    image_tag must follow the sentinelx-app-<assessment> naming policy.
    Build-time network must not be "host".
    """

    model_config = ConfigDict(extra="forbid")

    workspace_path: str = Field(..., description="Absolute path to the build context")
    image_tag: str = Field(..., description="Image tag to build")
    network_mode: str = Field(default="none", description="Docker build network mode")

    @field_validator("workspace_path")
    @classmethod
    def _validate_workspace_path(cls, v: str) -> str:
        base = settings.ASSESSMENT_WORKSPACE_BASE.rstrip("/")
        v = v.rstrip("/")
        if not v.startswith(base + "/") and v != base:
            raise ValueError(
                f"Build context must be under {settings.ASSESSMENT_WORKSPACE_BASE}"
            )
        return v

    @field_validator("image_tag")
    @classmethod
    def _validate_image_tag(cls, v: str) -> str:
        if not _is_valid_resource_name(v):
            raise ValueError(
                "Image tag must follow sentinelx-app-<assessment_id> naming policy"
            )
        return v

    @field_validator("network_mode")
    @classmethod
    def _validate_network_mode(cls, v: str) -> str:
        if v not in ("none", "internal"):
            raise ValueError(
                f"Build network mode '{v}' is not allowed; use 'none' or 'internal'"
            )
        return v


class NetworkCreateRequest(BaseModel):
    """Request to create an isolated internal network."""

    model_config = ConfigDict(extra="forbid")

    network_name: str = Field(..., description="Network name")
    internal: bool = Field(default=True, description="Must be true for isolation")

    @field_validator("network_name")
    @classmethod
    def _validate_network_name(cls, v: str) -> str:
        if not _is_valid_resource_name(v):
            raise ValueError(
                "Network name must follow sentinelx-net-<assessment_id> naming policy"
            )
        return v

    @field_validator("internal")
    @classmethod
    def _validate_internal(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError("Network must be internal (no external egress)")
        return v


class ContainerRunRequest(BaseModel):
    """Request to run a hardened container.

    Only minimal operational parameters are accepted. All security parameters
    (capabilities, privileges, mounts, network mode, user, resource limits)
    are enforced by the broker policy and are not part of this schema.
    """

    model_config = ConfigDict(extra="forbid")

    container_name: str = Field(..., description="Container name")
    image_tag: str = Field(..., description="Image tag to run")
    network_name: str = Field(..., description="Network to attach")
    app_port: int = Field(..., ge=1024, le=65535, description="Application port inside container")
    host_port: int = Field(..., ge=1024, le=65535, description="Host loopback port to publish")

    @field_validator("container_name", "image_tag", "network_name")
    @classmethod
    def _validate_names(cls, v: str) -> str:
        if not _is_valid_resource_name(v):
            raise ValueError(
                f"Resource name '{v}' does not follow sentinelx-*-<assessment_id> naming policy"
            )
        return v

    @model_validator(mode="after")
    def _validate_consistency(self) -> "ContainerRunRequest":
        # Derive assessment id from each name and ensure they refer to the same assessment.
        names = {
            "container_name": self.container_name,
            "image_tag": self.image_tag,
            "network_name": self.network_name,
        }
        assessment_ids = set()
        for label, name in names.items():
            parts = name.split("-")
            if len(parts) < 3:
                raise ValueError(f"{label} '{name}' is missing assessment id")
            assessment_ids.add(parts[-1])
        if len(assessment_ids) != 1:
            raise ValueError(
                "container_name, image_tag, and network_name must reference the same assessment."
            )
        return self


class CleanupRequest(BaseModel):
    """Request to clean up all resources for an assessment."""

    model_config = ConfigDict(extra="forbid")

    container_name: str = Field(..., description="Container name")
    network_name: str = Field(..., description="Network name")
    image_tag: str = Field(..., description="Image tag")

    @field_validator("container_name", "image_tag", "network_name")
    @classmethod
    def _validate_names(cls, v: str) -> str:
        if not _is_valid_resource_name(v):
            raise ValueError(
                f"Resource name '{v}' does not follow sentinelx-*-<assessment_id> naming policy"
            )
        return v


class HealthResponse(BaseModel):
    """Broker health response."""

    status: str
    service: str = "sentinelx-runtime-broker"
    docker_available: bool = False
