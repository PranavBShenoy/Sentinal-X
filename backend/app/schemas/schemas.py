"""
Pydantic v2 schemas for SENTINEL-X API.

All API request/response models are defined here. These enforce
type safety and validation at the boundary. Schemas deliberately
exclude sensitive fields (passwords, tokens, encryption keys).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


# ---------------------------------------------------------------------------
# Base / Shared
# ---------------------------------------------------------------------------


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class PaginatedResponse(BaseSchema):
    total: int
    page: int
    page_size: int
    items: List[Any]


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(min_length=12, max_length=128)

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseSchema):
    id: UUID
    email: str
    username: str
    is_active: bool
    is_verified: bool
    github_username: Optional[str] = None
    created_at: datetime


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)


class ProjectResponse(BaseSchema):
    id: UUID
    name: str
    description: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]


# ---------------------------------------------------------------------------
# Repositories
# ---------------------------------------------------------------------------


class RepositoryCreate(BaseModel):
    full_name: str = Field(description="GitHub full name e.g. owner/repo")
    github_repo_id: Optional[str] = None
    clone_url: Optional[str] = None
    default_branch: Optional[str] = None
    is_private: bool = False


class RepositoryResponse(BaseSchema):
    id: UUID
    project_id: UUID
    full_name: str
    default_branch: Optional[str]
    is_private: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------


class AssessmentConfig(BaseModel):
    """User-provided assessment configuration."""
    enable_active_dast: bool = False
    enable_git_history_scan: bool = False
    target_url: Optional[str] = Field(None, description="Existing staging URL to test")
    openapi_spec_url: Optional[str] = None
    # Test credentials (encrypted at rest, never logged)
    test_username: Optional[str] = None
    test_password: Optional[str] = None  # Will be encrypted before storage
    scan_depth: str = Field(default="standard", pattern=r"^(quick|standard|deep)$")
    # Maximum concurrent scanners
    max_concurrent_scanners: int = Field(default=2, ge=1, le=4)


class AssessmentCreate(BaseModel):
    repository_id: UUID
    branch: Optional[str] = None
    commit_sha: Optional[str] = Field(None, pattern=r"^[a-f0-9]{40}$")
    config: Optional[AssessmentConfig] = None


class AssessmentResponse(BaseSchema):
    id: UUID
    project_id: UUID
    repository_id: Optional[UUID]
    commit_sha: Optional[str]
    branch: Optional[str]
    target_url: Optional[str]
    status: str
    current_stage: Optional[str]
    risk_score: Optional[float]
    risk_level: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]


class AssessmentProgress(BaseSchema):
    assessment_id: UUID
    status: str
    current_stage: Optional[str]
    scan_jobs: List["ScanJobResponse"]
    runtime_status: Optional[str]
    findings_count: int


# ---------------------------------------------------------------------------
# Scan Jobs
# ---------------------------------------------------------------------------


class ScanJobResponse(BaseSchema):
    id: UUID
    tool_name: str
    status: str
    check_status: Optional[str]
    tool_version: Optional[str]
    findings_count: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    execution_time_seconds: Optional[float]
    error_message: Optional[str]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class FindingResponse(BaseSchema):
    id: UUID
    assessment_id: UUID
    title: str
    description: Optional[str]
    category: str
    subcategory: Optional[str]
    severity: str
    status: str
    confidence: str
    source_tool: str
    rule_id: Optional[str]
    file_path: Optional[str]
    line_start: Optional[int]
    line_end: Optional[int]
    endpoint: Optional[str]
    component: Optional[str]
    cve_ids: Optional[List[str]]
    cvss_score: Optional[float]
    affected_version: Optional[str]
    fixed_version: Optional[str]
    risk_score: Optional[float]
    risk_rationale: Optional[str]
    ai_explanation: Optional[str]
    ai_impact: Optional[str]
    ai_remediation_steps: Optional[List[str]]
    code_snippet: Optional[str]
    first_seen_at: datetime
    last_seen_at: datetime


class FindingUpdateRequest(BaseModel):
    status: str = Field(pattern=r"^(OPEN|CONFIRMED|FALSE_POSITIVE|ACCEPTED_RISK|SUPPRESSED)$")
    suppression_reason: Optional[str] = Field(None, max_length=2000)
    notes: Optional[str] = Field(None, max_length=2000)

    @field_validator("status", mode="before")
    @classmethod
    def normalize_status(cls, v: str) -> str:
        if isinstance(v, str):
            return v.strip().upper()
        return v


class FindingFilter(BaseModel):
    severity: Optional[List[str]] = None
    category: Optional[List[str]] = None
    status: Optional[List[str]] = None
    source_tool: Optional[str] = None
    search: Optional[str] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


# ---------------------------------------------------------------------------
# SBOM
# ---------------------------------------------------------------------------


class SbomComponentResponse(BaseSchema):
    id: UUID
    name: str
    version: Optional[str]
    purl: Optional[str]
    ecosystem: Optional[str]
    supplier: Optional[str]
    license_expression: Optional[str]
    is_direct: Optional[bool]
    vulnerability_matches: Optional[List[Any]]


class SbomArtifactResponse(BaseSchema):
    id: UUID
    format: str
    tool_name: str
    tool_version: Optional[str]
    component_count: int
    created_at: datetime
    components: List[SbomComponentResponse] = []


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------


class RuntimeStatusResponse(BaseSchema):
    assessment_id: UUID
    status: str
    adapter_type: Optional[str]
    target_url: Optional[str]
    health_check_passed: Optional[bool]
    failure_stage: Optional[str]
    failure_reason: Optional[str]
    safe_log_summary: Optional[str]
    provisioning_started_at: Optional[datetime]
    running_since: Optional[datetime]
    stopped_at: Optional[datetime]


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


class RemediationRequest(BaseModel):
    finding_id: UUID


class RemediationApprovalRequest(BaseModel):
    approved: bool
    rejection_reason: Optional[str] = Field(None, max_length=2000)


class RemediationResponse(BaseSchema):
    id: UUID
    assessment_id: UUID
    finding_id: UUID
    status: str
    summary: Optional[str]
    remediation_steps: Optional[List[str]]
    patch_diff: Optional[str]
    proposed_branch: Optional[str]
    approved_at: Optional[datetime]
    pr_url: Optional[str]
    created_at: datetime


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


class ReportGenerateRequest(BaseModel):
    format: str = Field(pattern=r"^(pdf|json|sarif|csv)$")


class ReportResponse(BaseSchema):
    id: UUID
    assessment_id: UUID
    format: str
    file_size_bytes: Optional[int]
    generated_at: datetime


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------


class GitHubAuthRequest(BaseModel):
    code: str  # OAuth authorization code
    state: Optional[str] = None


class GitHubRepoResponse(BaseModel):
    id: int
    full_name: str
    name: str
    private: bool
    default_branch: str
    clone_url: str
    description: Optional[str]
    language: Optional[str]
    updated_at: Optional[str]


# ---------------------------------------------------------------------------
# Error
# ---------------------------------------------------------------------------


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    request_id: Optional[str] = None


# Forward references
AssessmentProgress.model_rebuild()
