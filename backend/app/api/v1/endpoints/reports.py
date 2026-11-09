"""
Report Generation and Download API Endpoints.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.dependencies import get_assessment_or_404, get_current_user
from app.core.database import get_db
from app.models import Assessment, Project, Report, User
from app.reporting.generator import ReportGenerator
from app.schemas import ReportGenerateRequest, ReportResponse

router = APIRouter(tags=["reports"])


def get_report_or_404(
    report_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Report:
    """Dependency verifying report exists and belongs to current user's project."""
    report = (
        db.query(Report)
        .join(Assessment, Report.assessment_id == Assessment.id)
        .join(Project, Assessment.project_id == Project.id)
        .filter(Report.id == str(report_id), Project.owner_id == current_user.id)
        .first()
    )
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found or access denied.",
        )
    return report


@router.post(
    "/assessments/{assessment_id}/reports",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
)
def generate_report(
    assessment_id: UUID,
    payload: ReportGenerateRequest,
    assessment: Assessment = Depends(get_assessment_or_404),
    db: Session = Depends(get_db),
) -> ReportResponse:
    """Generate assessment report in specified format (pdf, json, sarif, csv)."""
    generator = ReportGenerator()
    result = generator.generate(str(assessment.id), format=payload.format)

    rep = db.query(Report).filter(Report.id == result["report_id"]).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Generated report not found.")
    return ReportResponse.model_validate(rep)


@router.get("/assessments/{assessment_id}/reports", response_model=List[ReportResponse])
def list_reports(
    assessment: Assessment = Depends(get_assessment_or_404),
    db: Session = Depends(get_db),
) -> List[ReportResponse]:
    """List all generated reports for an assessment."""
    reports = (
        db.query(Report)
        .filter(Report.assessment_id == assessment.id)
        .order_by(Report.generated_at.desc())
        .all()
    )
    return [ReportResponse.model_validate(r) for r in reports]


@router.get("/reports/{report_id}/download")
def download_report(
    report: Report = Depends(get_report_or_404),
) -> FileResponse:
    """Download a generated report file."""
    if not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file is not available on disk.",
        )

    # Determine media type
    media_types = {
        "pdf": "application/pdf",
        "json": "application/json",
        "sarif": "application/json",
        "csv": "text/csv",
    }
    media_type = media_types.get(report.format.lower(), "application/octet-stream")
    filename = Path(report.file_path).name

    return FileResponse(
        path=report.file_path,
        media_type=media_type,
        filename=filename,
    )
