"""
Job request/response schemas for the Runtime Host.

All schemas use ``extra = "forbid"`` to reject unexpected fields.
Responses are validated as untrusted data before being returned to the
control plane.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class JobSubmitRequest(BaseModel):
    """Request to submit a job to the Runtime Host."""

    model_config = {"extra": "forbid"}

    idempotency_key: str = Field(
        ..., description="Client-generated idempotency key for retries"
    )
    job_id: str = Field(..., description="Unique job identifier")
    tenant_id: str = Field(..., description="Owning tenant ID")
    assessment_id: str = Field(..., description="Owning assessment ID")
    operation: str = Field(
        ..., description="One of: build, run, cleanup, cancel"
    )
    resources: list[str] = Field(
        ..., description="Exact resource names this job may touch"
    )
    resource_limits: dict[str, Any] = Field(
        default_factory=dict,
        description="Resource limits (memory, CPUs, PIDs, disk, time)",
    )
    artifact_url: str | None = Field(
        None, description="Pre-signed URL to workspace tarball (build only)"
    )
    artifact_sha256: str | None = Field(
        None, description="SHA-256 of workspace tarball (build only)"
    )
    image_tag: str | None = Field(
        None, description="Docker image tag (generated internally if omitted)"
    )
    container_name: str | None = Field(
        None, description="Container name (generated internally if omitted)"
    )
    network_name: str | None = Field(
        None, description="Network name (generated internally if omitted)"
    )
    app_port: int | None = Field(
        None, description="Application port inside the container (run only)"
    )
    cpu_limit: Literal["1.0"]
    mem_limit: Literal["512m"]
    drop_capabilities: list[Literal["ALL"]]
    no_new_privileges: Literal[True]
    read_only_rootfs: Literal[True]

    @field_validator("drop_capabilities")
    @classmethod
    def require_all_capabilities_dropped(cls, value: list[str]) -> list[str]:
        if value != ["ALL"]:
            raise ValueError('drop_capabilities must equal ["ALL"]')
        return value

    @field_validator("operation")
    @classmethod
    def validate_operation(cls, v: str) -> str:
        allowed = {"build", "run", "cleanup", "cancel"}
        if v not in allowed:
            raise ValueError(f"Invalid operation: {v}. Must be one of {allowed}")
        return v

    @field_validator("app_port")
    @classmethod
    def validate_app_port(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 65535):
            raise ValueError(f"Invalid app_port: {v}. Must be 1-65535")
        return v


class JobSubmitResponse(BaseModel):
    """Response from job submission."""

    model_config = {"extra": "forbid"}

    job_id: str
    status: str
    message: str
    target_url: str | None = None
    expires_at: str | None = None


class JobStatusResponse(BaseModel):
    """Response from job status query."""

    model_config = {"extra": "forbid"}

    job_id: str
    status: str
    target_url: str | None = None
    error: str | None = None
    created_at: str | None = None
    completed_at: str | None = None


class JobLogsResponse(BaseModel):
    """Response from job logs query."""

    model_config = {"extra": "forbid"}

    job_id: str
    logs: str


class JobCancelResponse(BaseModel):
    """Response from job cancellation."""

    model_config = {"extra": "forbid"}

    job_id: str
    status: str
    message: str


class HealthResponse(BaseModel):
    """Response from health check."""

    model_config = {"extra": "forbid"}

    status: str
    docker_available: bool
