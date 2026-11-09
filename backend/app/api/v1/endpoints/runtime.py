"""
Runtime Environment API Endpoints.

Provides isolated Docker provisioning status, health check outcomes,
and safe diagnostic container logs with secrets redacted.
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_assessment_or_404
from app.core.database import get_db
from app.models import Assessment, RuntimeEnvironment
from app.schemas import RuntimeStatusResponse

router = APIRouter(tags=["runtime"])


@router.get("/assessments/{assessment_id}/runtime", response_model=RuntimeStatusResponse)
def get_runtime_status(
    assessment: Assessment = Depends(get_assessment_or_404),
    db: Session = Depends(get_db),
) -> RuntimeStatusResponse:
    """Retrieve runtime Docker container status and health check state."""
    env = (
        db.query(RuntimeEnvironment)
        .filter(RuntimeEnvironment.assessment_id == assessment.id)
        .first()
    )
    if not env:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No runtime environment record found for this assessment.",
        )
    return RuntimeStatusResponse.model_validate(env)


@router.get("/assessments/{assessment_id}/runtime/logs", response_model=dict)
def get_runtime_logs(
    assessment: Assessment = Depends(get_assessment_or_404),
    db: Session = Depends(get_db),
) -> dict:
    """Get redacted container build and startup logs."""
    env = (
        db.query(RuntimeEnvironment)
        .filter(RuntimeEnvironment.assessment_id == assessment.id)
        .first()
    )
    if not env:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No runtime environment record found for this assessment.",
        )

    return {
        "assessment_id": assessment.id,
        "status": env.status.value,
        "failure_stage": env.failure_stage,
        "failure_reason": env.failure_reason,
        "logs": env.safe_log_summary or "No runtime logs recorded.",
    }
