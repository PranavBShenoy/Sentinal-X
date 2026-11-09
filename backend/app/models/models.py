"""
SENTINEL-X Database Models — All ORM entities.

Design principles:
- UUIDs as primary keys (not sequential integers that enable enumeration)
- Timestamps in UTC
- Ownership enforced at model and service layer
- Sensitive values encrypted before storage
- JSONB only for genuinely flexible scanner metadata
- Meaningful indexes for common query patterns
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.core.database import Base

# Universal JSON and UUID types compatible with PostgreSQL (production) and SQLite (tests)
JSONType = JSON().with_variant(JSONB, "postgresql")
UUIDType = String(36).with_variant(UUID(as_uuid=False), "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AssessmentStatus(str, enum.Enum):
    CREATED = "CREATED"
    REPOSITORY_FETCH = "REPOSITORY_FETCH"
    REPOSITORY_ANALYSIS = "REPOSITORY_ANALYSIS"
    STATIC_SCANS = "STATIC_SCANS"
    SBOM_GENERATION = "SBOM_GENERATION"
    DEPENDENCY_ANALYSIS = "DEPENDENCY_ANALYSIS"
    RUNTIME_PROVISIONING = "RUNTIME_PROVISIONING"
    DYNAMIC_TESTING = "DYNAMIC_TESTING"
    FINDING_NORMALIZATION = "FINDING_NORMALIZATION"
    CORRELATION_AND_RISK = "CORRELATION_AND_RISK"
    AI_ANALYSIS = "AI_ANALYSIS"
    REPORT_GENERATION = "REPORT_GENERATION"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanJobStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    SKIPPED = "SKIPPED"


class CheckStatus(str, enum.Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    NOT_ASSESSED = "NOT_ASSESSED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FIXED = "FIXED"
    SUPPRESSED = "SUPPRESSED"


class FindingCategory(str, enum.Enum):
    SAST = "SAST"
    SECRET = "SECRET"
    DEPENDENCY = "DEPENDENCY"
    CONTAINER = "CONTAINER"
    DAST = "DAST"
    CONFIGURATION = "CONFIGURATION"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"


class ConfidenceLevel(str, enum.Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class RuntimeStatus(str, enum.Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    BUILDING = "BUILDING"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    HEALTH_CHECK_FAILED = "HEALTH_CHECK_FAILED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"
    UNSUPPORTED = "UNSUPPORTED"
    CLEANUP_DONE = "CLEANUP_DONE"


class RemediationStatus(str, enum.Enum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"
    INCONCLUSIVE = "INCONCLUSIVE"


# ---------------------------------------------------------------------------
# Users and Authentication
# ---------------------------------------------------------------------------


class User(Base):
    __tablename__ = "users"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=True)  # Null for OAuth-only users
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # GitHub OAuth info (non-sensitive)
    github_user_id = Column(String(100), nullable=True, unique=True)
    github_username = Column(String(100), nullable=True)

    # Relationships
    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    user_id = Column(UUIDType, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    refresh_token_hash = Column(String(64), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    user = relationship("User", back_populates="sessions")

    __table_args__ = (
        Index("ix_user_sessions_user_id", "user_id"),
    )


# ---------------------------------------------------------------------------
# GitHub Installations
# ---------------------------------------------------------------------------


class GitHubInstallation(Base):
    """Secure reference to a GitHub App installation or OAuth token."""
    __tablename__ = "github_installations"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    user_id = Column(UUIDType, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    installation_id = Column(String(100), nullable=True)  # GitHub App installation ID
    # Encrypted GitHub access token for OAuth integrations
    encrypted_access_token = Column(Text, nullable=True)
    token_expires_at = Column(DateTime(timezone=True), nullable=True)
    scope = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User")

    __table_args__ = (
        Index("ix_github_installations_user_id", "user_id"),
    )


# ---------------------------------------------------------------------------
# Projects and Repositories
# ---------------------------------------------------------------------------


class Project(Base):
    __tablename__ = "projects"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    owner_id = Column(UUIDType, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    owner = relationship("User", back_populates="projects")
    repositories = relationship("Repository", back_populates="project", cascade="all, delete-orphan")
    assessments = relationship("Assessment", back_populates="project", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_projects_owner_id", "owner_id"),
    )


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    project_id = Column(UUIDType, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    github_repo_id = Column(String(100), nullable=True)
    full_name = Column(String(500), nullable=False)  # e.g. "owner/repo"
    clone_url = Column(String(1000), nullable=True)
    default_branch = Column(String(200), nullable=True)
    is_private = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    project = relationship("Project", back_populates="repositories")
    assessments = relationship("Assessment", back_populates="repository")


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    project_id = Column(UUIDType, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    repository_id = Column(UUIDType, ForeignKey("repositories.id"), nullable=True)
    created_by_id = Column(UUIDType, ForeignKey("users.id"), nullable=False)

    # What we're assessing
    commit_sha = Column(String(40), nullable=True)
    branch = Column(String(200), nullable=True)
    target_url = Column(String(2000), nullable=True)  # Optional staging URL

    # Pipeline state
    status = Column(Enum(AssessmentStatus), default=AssessmentStatus.CREATED, nullable=False)
    current_stage = Column(String(100), nullable=True)

    # Timing
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Assessment config (scan depth, active test permissions, etc.)
    config = Column(JSONType, nullable=True, default=dict)

    # Repository analysis results
    repo_analysis = Column(JSONType, nullable=True)

    # Overall risk summary (computed)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)

    # Error/failure details
    error_message = Column(Text, nullable=True)

    # Relationships
    project = relationship("Project", back_populates="assessments")
    repository = relationship("Repository", back_populates="assessments")
    scan_jobs = relationship("ScanJob", back_populates="assessment", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="assessment", cascade="all, delete-orphan")
    sbom_artifacts = relationship("SbomArtifact", back_populates="assessment", cascade="all, delete-orphan")
    runtime_environment = relationship("RuntimeEnvironment", back_populates="assessment", uselist=False)
    remediation_proposals = relationship("RemediationProposal", back_populates="assessment")
    reports = relationship("Report", back_populates="assessment", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_assessments_project_id", "project_id"),
        Index("ix_assessments_status", "status"),
        Index("ix_assessments_created_at", "created_at"),
    )


class ScanJob(Base):
    """Individual scanner execution within an assessment."""
    __tablename__ = "scan_jobs"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    assessment_id = Column(UUIDType, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    tool_name = Column(String(100), nullable=False)  # semgrep, gitleaks, syft, etc.
    status = Column(Enum(ScanJobStatus), default=ScanJobStatus.PENDING, nullable=False)
    check_status = Column(Enum(CheckStatus), nullable=True)  # Security result status

    # Execution metadata
    tool_version = Column(String(100), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    exit_code = Column(Integer, nullable=True)
    execution_time_seconds = Column(Float, nullable=True)

    # Raw output stored as reference (not in DB for size reasons — stored as file)
    raw_output_path = Column(String(2000), nullable=True)

    # Safe diagnostic info (secrets must be redacted before storing)
    safe_stderr_summary = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)

    # Scanner-specific metadata (column name mapped to avoid reserved 'metadata' attr)
    job_metadata = Column("metadata", JSONType, nullable=True, default=dict)

    # Findings count (denormalized for quick summary)
    findings_count = Column(Integer, default=0)

    assessment = relationship("Assessment", back_populates="scan_jobs")

    __table_args__ = (
        Index("ix_scan_jobs_assessment_id", "assessment_id"),
        Index("ix_scan_jobs_tool_name", "tool_name"),
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class Finding(Base):
    """Normalised security finding from any scanner."""
    __tablename__ = "findings"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    assessment_id = Column(UUIDType, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    scan_job_id = Column(UUIDType, ForeignKey("scan_jobs.id"), nullable=True)

    # Stable fingerprint for deduplication across rescans
    fingerprint = Column(String(64), nullable=True, index=True)

    # Classification
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(Enum(FindingCategory), nullable=False)
    subcategory = Column(String(200), nullable=True)
    severity = Column(Enum(FindingSeverity), nullable=False)
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN, nullable=False)
    confidence = Column(Enum(ConfidenceLevel), default=ConfidenceLevel.UNKNOWN)

    # Source
    source_tool = Column(String(100), nullable=False)
    rule_id = Column(String(500), nullable=True)

    # Location
    file_path = Column(String(2000), nullable=True)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    endpoint = Column(String(2000), nullable=True)
    component = Column(String(500), nullable=True)

    # Vulnerability intelligence
    cve_ids = Column(JSONType, nullable=True, default=list)
    advisory_ids = Column(JSONType, nullable=True, default=list)
    cvss_score = Column(Float, nullable=True)
    affected_version = Column(String(200), nullable=True)
    fixed_version = Column(String(200), nullable=True)

    # Risk analysis
    risk_score = Column(Float, nullable=True)
    risk_rationale = Column(Text, nullable=True)

    # AI analysis
    ai_explanation = Column(Text, nullable=True)
    ai_impact = Column(Text, nullable=True)
    ai_remediation_steps = Column(JSONType, nullable=True, default=list)
    ai_confidence = Column(String(20), nullable=True)
    ai_limitations = Column(JSONType, nullable=True, default=list)

    # Code snippet — stored only where safe (no secrets)
    code_snippet = Column(Text, nullable=True)

    # Disposition
    suppression_reason = Column(Text, nullable=True)
    suppressed_by_id = Column(UUIDType, ForeignKey("users.id"), nullable=True)
    suppressed_at = Column(DateTime(timezone=True), nullable=True)

    # Timing
    first_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Raw scanner evidence (tool-specific fields)
    raw_evidence = Column(JSONType, nullable=True, default=dict)

    # Relationships
    assessment = relationship("Assessment", back_populates="findings")
    scan_job = relationship("ScanJob")
    remediation_proposals = relationship("RemediationProposal", back_populates="finding")

    __table_args__ = (
        Index("ix_findings_assessment_id", "assessment_id"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_category", "category"),
    )


# ---------------------------------------------------------------------------
# SBOM and Dependency Graph
# ---------------------------------------------------------------------------


class SbomArtifact(Base):
    """SBOM document generated for an assessment."""
    __tablename__ = "sbom_artifacts"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    assessment_id = Column(UUIDType, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    format = Column(String(50), nullable=False)  # cyclonedx-json, spdx-json
    tool_name = Column(String(100), nullable=False)  # syft
    tool_version = Column(String(100), nullable=True)
    component_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    # Path to raw SBOM file (not stored in DB for size)
    artifact_path = Column(String(2000), nullable=True)

    assessment = relationship("Assessment", back_populates="sbom_artifacts")
    components = relationship("SbomComponent", back_populates="sbom", cascade="all, delete-orphan")


class SbomComponent(Base):
    """Individual software component from an SBOM."""
    __tablename__ = "sbom_components"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    sbom_id = Column(UUIDType, ForeignKey("sbom_artifacts.id", ondelete="CASCADE"), nullable=False)
    assessment_id = Column(UUIDType, ForeignKey("assessments.id"), nullable=False)

    name = Column(String(500), nullable=False)
    version = Column(String(200), nullable=True)
    purl = Column(String(1000), nullable=True, index=True)  # Package URL
    ecosystem = Column(String(100), nullable=True)  # npm, pypi, maven, etc.
    supplier = Column(String(500), nullable=True)
    license_expression = Column(String(500), nullable=True)
    is_direct = Column(Boolean, nullable=True)  # None = unknown

    # Vulnerability matches
    vulnerability_matches = Column(JSONType, nullable=True, default=list)

    sbom = relationship("SbomArtifact", back_populates="components")

    __table_args__ = (
        Index("ix_sbom_components_sbom_id", "sbom_id"),
        Index("ix_sbom_components_assessment_id", "assessment_id"),
    )


class DependencyEdge(Base):
    """Dependency relationship for graph analysis."""
    __tablename__ = "dependency_edges"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    assessment_id = Column(UUIDType, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    source_purl = Column(String(1000), nullable=False)
    target_purl = Column(String(1000), nullable=False)
    relationship_type = Column(String(50), default="depends_on")  # depends_on, dev_depends_on

    __table_args__ = (
        Index("ix_dependency_edges_assessment_id", "assessment_id"),
    )


# ---------------------------------------------------------------------------
# Runtime Environment
# ---------------------------------------------------------------------------


class RuntimeEnvironment(Base):
    """Tracks Docker runtime provisioned for an assessment."""
    __tablename__ = "runtime_environments"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    assessment_id = Column(UUIDType, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, unique=True)

    status = Column(Enum(RuntimeStatus), default=RuntimeStatus.NOT_ATTEMPTED, nullable=False)
    adapter_type = Column(String(100), nullable=True)  # fastapi, flask, nodejs, etc.
    target_url = Column(String(500), nullable=True)  # URL of running app

    # Container identifiers (for cleanup)
    container_ids = Column(JSONType, nullable=True, default=list)
    network_id = Column(String(100), nullable=True)

    # Timing
    provisioning_started_at = Column(DateTime(timezone=True), nullable=True)
    running_since = Column(DateTime(timezone=True), nullable=True)
    stopped_at = Column(DateTime(timezone=True), nullable=True)
    cleanup_at = Column(DateTime(timezone=True), nullable=True)

    # Failure reason
    failure_stage = Column(String(100), nullable=True)
    failure_reason = Column(Text, nullable=True)

    # Health check results
    health_check_passed = Column(Boolean, nullable=True)
    health_check_url = Column(String(500), nullable=True)

    # Build/startup log summary (secrets must be redacted)
    safe_log_summary = Column(Text, nullable=True)

    assessment = relationship("Assessment", back_populates="runtime_environment")


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


class RemediationProposal(Base):
    __tablename__ = "remediation_proposals"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    assessment_id = Column(UUIDType, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    finding_id = Column(UUIDType, ForeignKey("findings.id"), nullable=False)
    created_by_id = Column(UUIDType, ForeignKey("users.id"), nullable=False)

    status = Column(Enum(RemediationStatus), default=RemediationStatus.PROPOSED, nullable=False)

    # AI-generated proposal
    summary = Column(Text, nullable=True)
    remediation_steps = Column(JSONType, nullable=True, default=list)
    patch_diff = Column(Text, nullable=True)
    proposed_branch = Column(String(500), nullable=True)

    # Approval tracking
    approved_by_id = Column(UUIDType, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    rejection_reason = Column(Text, nullable=True)

    # Verification
    verification_result = Column(Text, nullable=True)
    pr_url = Column(String(2000), nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    assessment = relationship("Assessment", back_populates="remediation_proposals")
    finding = relationship("Finding", back_populates="remediation_proposals")


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    assessment_id = Column(UUIDType, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    generated_by_id = Column(UUIDType, ForeignKey("users.id"), nullable=False)

    format = Column(String(20), nullable=False)  # pdf, json, sarif, csv
    file_path = Column(String(2000), nullable=True)
    file_size_bytes = Column(BigInteger, nullable=True)

    generated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    # Report metadata (column name mapped to avoid reserved 'metadata' attr)
    report_metadata = Column("metadata", JSONType, nullable=True, default=dict)

    assessment = relationship("Assessment", back_populates="reports")

    __table_args__ = (
        Index("ix_reports_assessment_id", "assessment_id"),
    )


# ---------------------------------------------------------------------------
# Audit Logs
# ---------------------------------------------------------------------------


class AuditLog(Base):
    """Immutable audit trail for security-sensitive actions."""
    __tablename__ = "audit_logs"

    id = Column(UUIDType, primary_key=True, default=new_uuid)
    user_id = Column(UUIDType, ForeignKey("users.id"), nullable=True)
    action = Column(String(200), nullable=False)
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    details = Column(JSONType, nullable=True, default=dict)  # Safe details only, no secrets
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_user_id", "user_id"),
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_created_at", "created_at"),
    )
