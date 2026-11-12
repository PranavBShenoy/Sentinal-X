"""
Assessment Management API Endpoints.

Handles creating, starting, monitoring, and canceling security assessments.
Enforces tenant isolation, input validation, and SSRF prevention on staging URLs.
"""
from __future__ import annotations

import uuid
from typing import Dict, List
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.dependencies import get_assessment_or_404, get_current_user, get_project_or_404, rate_limit
from app.core.database import get_db
from app.models import (
    Assessment,
    AssessmentStatus,
    AuthorizationRequest,
    CheckStatus,
    Finding,
    FindingSeverity,
    Project,
    Repository,
    ScanJob,
    User,
)
from app.schemas import (
    AssessmentCreate,
    AssessmentProgress,
    AssessmentResponse,
    PaginatedResponse,
    ScanJobResponse,
)

from app.core.ssrf import validate_target_url

router = APIRouter(tags=["assessments"])


@router.post(
    "/projects/{project_id}/assessments",
    response_model=AssessmentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_assessment(
    project_id: UUID,
    payload: AssessmentCreate,
    project: Project = Depends(get_project_or_404),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    _rl: None = Depends(rate_limit(max_calls=15, window_seconds=60, endpoint_key="assessment_create")),
) -> AssessmentResponse:
    """Create a new security assessment configuration."""
    repo = (
        db.query(Repository)
        .filter(Repository.id == str(payload.repository_id), Repository.project_id == project.id)
        .first()
    )
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found in this project.",
        )

    target_url = None
    config_dict = {}
    if payload.config:
        config_dict = payload.config.model_dump()
        target_url = payload.config.target_url
        if target_url:
            validate_target_url(target_url)

    assessment = Assessment(
        project_id=project.id,
        repository_id=repo.id,
        created_by_id=current_user.id,
        branch=payload.branch or repo.default_branch or "main",
        commit_sha=payload.commit_sha,
        target_url=target_url,
        config=config_dict,
        status=AssessmentStatus.CREATED,
    )
    db.add(assessment)
    db.flush()

    return AssessmentResponse.model_validate(assessment)


@router.post("/assessments/{assessment_id}/start", response_model=AssessmentResponse)
def start_assessment(
    assessment_id: UUID,
    background_tasks: BackgroundTasks,
    assessment: Assessment = Depends(get_assessment_or_404),
    db: Session = Depends(get_db),
) -> AssessmentResponse:
    """Trigger the assessment pipeline."""
    if assessment.status in (
        AssessmentStatus.REPOSITORY_FETCH,
        AssessmentStatus.STATIC_SCANS,
        AssessmentStatus.RUNTIME_PROVISIONING,
        AssessmentStatus.DYNAMIC_TESTING,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Assessment is already in progress.",
        )

    assessment.status = AssessmentStatus.REPOSITORY_FETCH
    assessment.current_stage = "QUEUED"

    # Create the durable authorization record in the same transaction as the
    # assessment status change, then commit before dispatch so the worker
    # (separate process/connection) can see it.
    request_id = str(uuid.uuid4())
    db.add(AuthorizationRequest(
        user_id=str(assessment.created_by_id),
        assessment_id=str(assessment.id),
        tenant_id=str(assessment.project.owner_id),
        operation="provision",
        request_id=request_id,
        status="pending",
    ))
    db.commit()

    # Attempt Celery task dispatch; if Redis/Celery is unavailable, run via
    # FastAPI BackgroundTasks with the same authorization checks.
    try:
        from app.workers.assessment_tasks import run_assessment
        run_assessment.delay(str(assessment.id), request_id=request_id)
    except Exception:
        from app.core.database import db_session as _db_session
        from app.services.assessment_pipeline import AssessmentPipeline
        from app.workers.assessment_tasks import _consume_authorization_request

        def _run_bg() -> None:
            # Consume the authorization atomically; fail closed on any error.
            with _db_session() as auth_session:
                _consume_authorization_request(
                    auth_session, str(assessment.id), request_id
                )
            AssessmentPipeline(
                str(assessment.id), request_id=request_id
            ).execute()

        background_tasks.add_task(_run_bg)

    db.refresh(assessment)
    return AssessmentResponse.model_validate(assessment)


@router.get("/assessments", response_model=PaginatedResponse)
def list_assessments(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PaginatedResponse:
    """List all assessments accessible to the current user."""
    base_q = (
        db.query(Assessment)
        .join(Project, Assessment.project_id == Project.id)
        .filter(Project.owner_id == current_user.id)
    )
    total = base_q.count()
    items = (
        base_q.order_by(Assessment.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PaginatedResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[AssessmentResponse.model_validate(a) for a in items],
    )


@router.get("/assessments/{assessment_id}", response_model=AssessmentResponse)
def get_assessment(
    assessment: Assessment = Depends(get_assessment_or_404),
) -> AssessmentResponse:
    """Get full details of a single assessment."""
    return AssessmentResponse.model_validate(assessment)


@router.get("/assessments/{assessment_id}/progress", response_model=AssessmentProgress)
def get_assessment_progress(
    assessment: Assessment = Depends(get_assessment_or_404),
    db: Session = Depends(get_db),
) -> AssessmentProgress:
    """Get real-time pipeline execution progress, scan job statuses, and findings count."""
    jobs = (
        db.query(ScanJob)
        .filter(ScanJob.assessment_id == assessment.id)
        .order_by(ScanJob.started_at.desc())
        .all()
    )

    findings_count = len(assessment.findings)
    runtime_status = (
        assessment.runtime_environment.status.value
        if assessment.runtime_environment
        else "NOT_ATTEMPTED"
    )

    # Ordered pipeline stages, matching the frontend telemetry view.
    pipeline_stages = [
        "REPOSITORY_FETCH",
        "STATIC_SCANS",
        "SBOM_GENERATION",
        "RUNTIME_PROVISIONING",
        "DYNAMIC_TESTING",
        "CORRELATION_AND_RISK",
        "AI_ANALYSIS",
    ]

    status_value = assessment.status.value
    terminal_statuses = {"COMPLETED", "PARTIAL", "FAILED", "CANCELLED"}
    stages: Dict[str, str] = {}
    if status_value in ("COMPLETED", "PARTIAL"):
        stages = {stage: "PASSED" for stage in pipeline_stages}
        completed_percentage = 100.0
    elif status_value in terminal_statuses:
        current = assessment.current_stage
        current_index = pipeline_stages.index(current) if current in pipeline_stages else -1
        stages = {
            stage: ("PASSED" if idx <= current_index else "PENDING")
            for idx, stage in enumerate(pipeline_stages)
        }
        completed_percentage = 0.0 if current_index < 0 else round(
            ((current_index + 1) / len(pipeline_stages)) * 100, 1
        )
    else:
        current = assessment.current_stage
        current_index = pipeline_stages.index(current) if current in pipeline_stages else -1
        stages = {
            stage: (
                "PASSED" if idx < current_index
                else "RUNNING" if idx == current_index
                else "PENDING"
            )
            for idx, stage in enumerate(pipeline_stages)
        }
        completed_percentage = 0.0 if current_index < 0 else round(
            (current_index / len(pipeline_stages)) * 100, 1
        )

    checks: Dict[str, str] = {}
    for job in jobs:
        if job.check_status:
            checks[job.tool_name] = job.check_status.value
        else:
            checks[job.tool_name] = job.status.value

    severity_counts = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.assessment_id == assessment.id)
        .group_by(Finding.severity)
        .all()
    )
    counts = {sev: count for sev, count in severity_counts}

    return AssessmentProgress(
        assessment_id=UUID(assessment.id),
        status=status_value,
        current_stage=assessment.current_stage,
        scan_jobs=[ScanJobResponse.model_validate(j) for j in jobs],
        runtime_status=runtime_status,
        findings_count=findings_count,
        completed_percentage=completed_percentage,
        stages=stages,
        checks=checks,
        critical_count=counts.get(FindingSeverity.CRITICAL, 0),
        high_count=counts.get(FindingSeverity.HIGH, 0),
        medium_count=counts.get(FindingSeverity.MEDIUM, 0),
        low_count=counts.get(FindingSeverity.LOW, 0),
    )


@router.get("/assessments/{assessment_id}/jobs", response_model=List[ScanJobResponse])
def list_assessment_jobs(
    assessment: Assessment = Depends(get_assessment_or_404),
    db: Session = Depends(get_db),
) -> List[ScanJobResponse]:
    """List scanner jobs for an assessment (tenant-isolated)."""
    jobs = (
        db.query(ScanJob)
        .filter(ScanJob.assessment_id == assessment.id)
        .order_by(ScanJob.started_at.desc())
        .all()
    )
    return [ScanJobResponse.model_validate(job) for job in jobs]


@router.delete("/assessments/{assessment_id}/cancel", response_model=AssessmentResponse)
def cancel_assessment(
    assessment: Assessment = Depends(get_assessment_or_404),
    db: Session = Depends(get_db),
) -> AssessmentResponse:
    """Cancel an in-progress assessment."""
    if assessment.status in (AssessmentStatus.COMPLETED, AssessmentStatus.CANCELLED, AssessmentStatus.FAILED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel assessment in state '{assessment.status.value}'.",
        )

    assessment.status = AssessmentStatus.CANCELLED
    db.flush()

    # Trigger runtime cleanup
    try:
        from app.runtime.docker.orchestrator import RuntimeOrchestrator
        RuntimeOrchestrator().cleanup(str(assessment.id))
    except Exception:
        pass

    return AssessmentResponse.model_validate(assessment)


@router.get("/assessments/{assessment_id}/coverage", response_model=dict)
def get_assessment_coverage(
    assessment: Assessment = Depends(get_assessment_or_404),
    db: Session = Depends(get_db),
) -> dict:
    """Get comprehensive security assessment coverage metrics."""
    jobs = (
        db.query(ScanJob)
        .filter(ScanJob.assessment_id == assessment.id)
        .all()
    )

    passed_count = sum(1 for j in jobs if j.check_status == CheckStatus.PASSED)
    failed_count = sum(1 for j in jobs if j.check_status == CheckStatus.FAILED)
    blocked_count = sum(1 for j in jobs if j.check_status == CheckStatus.BLOCKED)
    not_assessed_count = sum(1 for j in jobs if j.check_status == CheckStatus.NOT_ASSESSED)

    return {
        "assessment_id": assessment.id,
        "total_checks_planned": len(jobs),
        "checks_passed": passed_count,
        "checks_failed": failed_count,
        "checks_blocked": blocked_count,
        "checks_not_assessed": not_assessed_count,
        "runtime_provisioned": bool(
            assessment.runtime_environment
            and assessment.runtime_environment.health_check_passed
        ),
        "overall_status": assessment.status.value,
        "coverage_percentage": round((passed_count + failed_count) / max(len(jobs), 1) * 100, 1),
    }
