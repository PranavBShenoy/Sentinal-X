"""
Projects CRUD endpoints for SENTINEL-X.
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, get_project_or_404
from app.core.database import get_db
from app.models.models import Project, User
from app.schemas.schemas import (
    PaginatedResponse,
    ProjectCreate,
    ProjectResponse,
    ProjectUpdate,
)

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ProjectResponse:
    project = Project(
        owner_id=current_user.id,
        name=payload.name,
        description=payload.description,
    )
    db.add(project)
    db.flush()
    return ProjectResponse.model_validate(project)


@router.get("", response_model=PaginatedResponse)
def list_projects(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PaginatedResponse:
    base_q = db.query(Project).filter(Project.owner_id == current_user.id)
    total = base_q.count()
    items = (
        base_q.order_by(Project.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return PaginatedResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[ProjectResponse.model_validate(p) for p in items],
    )


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(
    project: Project = Depends(get_project_or_404),
) -> ProjectResponse:
    return ProjectResponse.model_validate(project)


@router.put("/{project_id}", response_model=ProjectResponse)
def update_project(
    payload: ProjectUpdate,
    project: Project = Depends(get_project_or_404),
    db: Session = Depends(get_db),
) -> ProjectResponse:
    if payload.name is not None:
        project.name = payload.name
    if payload.description is not None:
        project.description = payload.description
    db.flush()
    return ProjectResponse.model_validate(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project: Project = Depends(get_project_or_404),
    db: Session = Depends(get_db),
) -> None:
    db.delete(project)
    db.flush()
