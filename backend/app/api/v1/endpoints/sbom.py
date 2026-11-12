"""
Software Bill of Materials (SBOM) and Dependency Graph API Endpoints.
"""
from __future__ import annotations

from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.analysis.dependency_graph.builder import DependencyGraphBuilder
from app.api.dependencies import get_assessment_or_404
from app.core.database import get_db
from app.models import Assessment, SbomArtifact, SbomComponent
from app.schemas import SbomArtifactResponse, SbomComponentResponse

router = APIRouter(tags=["sbom"])


@router.get("/assessments/{assessment_id}/sbom", response_model=List[SbomArtifactResponse])
def get_assessment_sboms(
    assessment: Assessment = Depends(get_assessment_or_404),
    db: Session = Depends(get_db),
) -> List[SbomArtifactResponse]:
    """List SBOM artifacts generated for an assessment."""
    sboms = (
        db.query(SbomArtifact)
        .filter(SbomArtifact.assessment_id == assessment.id)
        .all()
    )
    return [SbomArtifactResponse.model_validate(s) for s in sboms]


@router.get("/assessments/{assessment_id}/sbom/{sbom_id}/components", response_model=List[SbomComponentResponse])
def get_sbom_components(
    assessment_id: UUID,
    sbom_id: UUID,
    assessment: Assessment = Depends(get_assessment_or_404),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> List[SbomComponentResponse]:
    """List software components identified in an SBOM."""
    components = (
        db.query(SbomComponent)
        .filter(SbomComponent.sbom_id == str(sbom_id), SbomComponent.assessment_id == assessment.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return [SbomComponentResponse.model_validate(c) for c in components]


@router.get("/assessments/{assessment_id}/dependencies/graph", response_model=dict)
@router.get("/assessments/{assessment_id}/dependency-graph", response_model=dict)
def get_dependency_graph(
    assessment: Assessment = Depends(get_assessment_or_404),
) -> dict:
    """Get directed dependency graph nodes and edges for visualization."""
    builder = DependencyGraphBuilder()
    return builder.get_visualization_payload(str(assessment.id))
