"""
Findings Management API Endpoints.

Provides search, filtering, pagination, and status updates for security findings.
"""
from __future__ import annotations

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.dependencies import get_assessment_or_404, get_current_user
from app.core.database import get_db
from app.models import (
    Assessment,
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    Project,
    User,
)
from app.schemas import (
    FindingResponse,
    FindingUpdateRequest,
    PaginatedResponse,
)

router = APIRouter(tags=["findings"])


def get_finding_or_404(
    finding_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Finding:
    """Dependency ensuring finding exists and belongs to a project owned by current_user."""
    finding = (
        db.query(Finding)
        .join(Assessment, Finding.assessment_id == Assessment.id)
        .join(Project, Assessment.project_id == Project.id)
        .filter(Finding.id == str(finding_id), Project.owner_id == current_user.id)
        .first()
    )
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found or access denied.",
        )
    return finding


@router.get("/findings", response_model=PaginatedResponse)
def list_findings(
    assessment_id: Optional[UUID] = Query(None),
    severity: Optional[str] = Query(None, description="Comma-separated severity values"),
    category: Optional[str] = Query(None, description="Comma-separated category values"),
    status_filter: Optional[str] = Query(None, alias="status"),
    source_tool: Optional[str] = Query(None, alias="tool_name"),
    search: Optional[str] = Query(None),
    sort_by: str = Query(default="risk_score", pattern=r"^(risk_score|severity|first_seen_at)$"),
    sort_dir: str = Query(default="desc", pattern=r"^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PaginatedResponse:
    """Filter, sort, and paginate security findings across user projects or for a specific assessment."""
    query = (
        db.query(Finding)
        .join(Assessment, Finding.assessment_id == Assessment.id)
        .join(Project, Assessment.project_id == Project.id)
        .filter(Project.owner_id == current_user.id)
    )

    if assessment_id:
        query = query.filter(Finding.assessment_id == assessment_id)

    if severity:
        sev_list = [s.strip().upper() for s in severity.split(",") if s.strip()]
        query = query.filter(Finding.severity.in_(sev_list))

    if category:
        cat_list = [c.strip().upper() for c in category.split(",") if c.strip()]
        query = query.filter(Finding.category.in_(cat_list))

    if status_filter:
        query = query.filter(Finding.status == status_filter.upper())

    if source_tool:
        query = query.filter(Finding.source_tool == source_tool.lower())

    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Finding.title.ilike(pattern),
                Finding.description.ilike(pattern),
                Finding.file_path.ilike(pattern),
                Finding.component.ilike(pattern),
            )
        )

    # Sorting
    if sort_by == "risk_score":
        sort_col = Finding.risk_score.desc().nullslast() if sort_dir == "desc" else Finding.risk_score.asc().nullsfirst()
    elif sort_by == "first_seen_at":
        sort_col = Finding.first_seen_at.desc() if sort_dir == "desc" else Finding.first_seen_at.asc()
    else:
        sort_col = Finding.severity.desc() if sort_dir == "desc" else Finding.severity.asc()

    total = query.count()
    items = query.order_by(sort_col).offset((page - 1) * page_size).limit(page_size).all()

    return PaginatedResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[FindingResponse.model_validate(f) for f in items],
    )


@router.get("/assessments/{assessment_id}/findings", response_model=PaginatedResponse)
def list_assessment_findings(
    assessment_id: UUID,
    assessment: Assessment = Depends(get_assessment_or_404),
    severity: Optional[str] = Query(None, description="Comma-separated severity values"),
    category: Optional[str] = Query(None, description="Comma-separated category values"),
    status_filter: Optional[str] = Query(None, alias="status"),
    source_tool: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: str = Query(default="risk_score", pattern=r"^(risk_score|severity|first_seen_at)$"),
    sort_dir: str = Query(default="desc", pattern=r"^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> PaginatedResponse:
    """Filter, sort, and paginate security findings for an assessment."""
    query = db.query(Finding).filter(Finding.assessment_id == assessment.id)

    if severity:
        sev_list = [s.strip().upper() for s in severity.split(",") if s.strip()]
        query = query.filter(Finding.severity.in_(sev_list))

    if category:
        cat_list = [c.strip().upper() for c in category.split(",") if c.strip()]
        query = query.filter(Finding.category.in_(cat_list))

    if status_filter:
        query = query.filter(Finding.status == status_filter.upper())

    if source_tool:
        query = query.filter(Finding.source_tool == source_tool.lower())

    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Finding.title.ilike(pattern),
                Finding.description.ilike(pattern),
                Finding.file_path.ilike(pattern),
                Finding.component.ilike(pattern),
            )
        )

    # Sorting
    if sort_by == "risk_score":
        sort_col = Finding.risk_score.desc().nullslast() if sort_dir == "desc" else Finding.risk_score.asc().nullsfirst()
    elif sort_by == "first_seen_at":
        sort_col = Finding.first_seen_at.desc() if sort_dir == "desc" else Finding.first_seen_at.asc()
    else:
        sort_col = Finding.severity.desc() if sort_dir == "desc" else Finding.severity.asc()

    total = query.count()
    items = query.order_by(sort_col).offset((page - 1) * page_size).limit(page_size).all()

    return PaginatedResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[FindingResponse.model_validate(f) for f in items],
    )


@router.get("/findings/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding: Finding = Depends(get_finding_or_404),
) -> FindingResponse:
    """Get single finding detail."""
    return FindingResponse.model_validate(finding)


@router.put("/findings/{finding_id}", response_model=FindingResponse)
@router.patch("/findings/{finding_id}/disposition", response_model=FindingResponse)
def update_finding_disposition(
    payload: FindingUpdateRequest,
    finding: Finding = Depends(get_finding_or_404),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FindingResponse:
    """Update finding status (e.g. mark as FALSE_POSITIVE, ACCEPTED_RISK, or SUPPRESSED with reason)."""
    finding.status = FindingStatus(payload.status)
    reason = payload.suppression_reason or payload.notes
    if reason:
        finding.suppression_reason = reason
        finding.suppressed_by_id = current_user.id
    db.flush()
    return FindingResponse.model_validate(finding)


@router.get("/assessments/{assessment_id}/findings/summary", response_model=dict)
def get_findings_summary(
    assessment: Assessment = Depends(get_assessment_or_404),
    db: Session = Depends(get_db),
) -> dict:
    """Get count of findings grouped by severity and category."""
    findings = db.query(Finding).filter(Finding.assessment_id == assessment.id).all()

    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_category = {}

    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        by_category[f.category.value] = by_category.get(f.category.value, 0) + 1

    return {
        "assessment_id": assessment.id,
        "total": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
    }
