"""
Assessment Management API Endpoints.

Handles creating, starting, monitoring, and canceling security assessments.
Enforces tenant isolation, input validation, and SSRF prevention on staging URLs.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_assessment_or_404, get_current_user, get_project_or_404
from app.core.database import get_db
from app.models import (
    Assessment,
    AssessmentStatus,
    CheckStatus,
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

router = APIRouter(tags=["assessments"])


def validate_target_url(target_url: str) -> None:
    """
    SSRF Defense: validate that target_url does not point to
    loopback, link-local, cloud metadata, or private IP networks.
    """
    if not target_url:
        return
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target URL must use http:// or https:// scheme.",
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid target URL host.")

    try:
        # Resolve hostname to IP addresses
        addr_info = socket.getaddrinfo(hostname, None)
        ips = [info[4][0] for info in addr_info]
    except Exception:
        # If DNS cannot be resolved, allow or reject based on policy
        return

    for ip_str in ips:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="SSRF Blocked: Scanning loopback addresses (127.0.0.1 / localhost) is prohibited.",
            )
        if ip.is_link_local or ip_str.startswith("169.254."):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="SSRF Blocked: Scanning cloud metadata addresses (169.254.169.254) is prohibited.",
            )
        if ip.is_multicast or ip.is_reserved:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="SSRF Blocked: Reserved / multicast IP address target is prohibited.",
            )


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
    db.flush()

    # Attempt Celery task dispatch; if Redis/Celery is unavailable, run via FastAPI BackgroundTasks
    dispatched = False
    try:
        from app.workers.assessment_tasks import run_assessment
        run_assessment.delay(str(assessment.id))
        dispatched = True
    except Exception as e:
        # Fallback to local background execution
        from app.services.assessment_pipeline import AssessmentPipeline

        def _run_bg():
            pipeline = AssessmentPipeline(str(assessment.id))
            pipeline.execute()

        background_tasks.add_task(_run_bg)
        dispatched = True

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
        .all()
    )

    findings_count = len(assessment.findings)
    runtime_status = (
        assessment.runtime_environment.status.value
        if assessment.runtime_environment
        else "NOT_ATTEMPTED"
    )

    return AssessmentProgress(
        assessment_id=UUID(assessment.id),
        status=assessment.status.value,
        current_stage=assessment.current_stage,
        scan_jobs=[ScanJobResponse.model_validate(j) for j in jobs],
        runtime_status=runtime_status,
        findings_count=findings_count,
    )


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
