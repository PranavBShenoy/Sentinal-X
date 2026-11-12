"""
Repository management endpoints for SENTINEL-X.
"""
from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, get_project_or_404
from app.core.database import get_db
from app.models.models import GitHubInstallation, Project, Repository, User
from app.schemas.schemas import RepositoryCreate, RepositoryResponse
from app.services.github_service import github_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["repositories"])


# --------------------------------------------------------------------------- #
# Per-project repository management
# --------------------------------------------------------------------------- #

@router.post(
    "/projects/{project_id}/repositories",
    response_model=RepositoryResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_repository(
    payload: RepositoryCreate,
    project: Project = Depends(get_project_or_404),
    db: Session = Depends(get_db),
) -> RepositoryResponse:
    repo = Repository(
        project_id=project.id,
        full_name=payload.full_name,
        github_repo_id=payload.github_repo_id,
        clone_url=payload.clone_url,
        default_branch=payload.default_branch or "main",
        is_private=payload.is_private,
    )
    db.add(repo)
    db.flush()
    return RepositoryResponse.model_validate(repo)


@router.get(
    "/projects/{project_id}/repositories",
    response_model=list[RepositoryResponse],
)
def list_repositories(
    project: Project = Depends(get_project_or_404),
    db: Session = Depends(get_db),
) -> list[RepositoryResponse]:
    repos = (
        db.query(Repository)
        .filter(Repository.project_id == project.id)
        .order_by(Repository.created_at.desc())
        .all()
    )
    return [RepositoryResponse.model_validate(r) for r in repos]


# --------------------------------------------------------------------------- #
# GitHub repository listing (OAuth)
# --------------------------------------------------------------------------- #

@router.get("/repositories/github", response_model=list[dict])
async def list_github_repos(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    """List GitHub repositories accessible to the authenticated user."""
    installation = (
        db.query(GitHubInstallation)
        .filter(
            GitHubInstallation.user_id == current_user.id,
            GitHubInstallation.revoked_at.is_(None),
        )
        .first()
    )
    if not installation or not installation.encrypted_access_token:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="GitHub account not connected. Complete GitHub OAuth first.",
        )

    from app.core.security import decrypt_value

    try:
        access_token = decrypt_value(installation.encrypted_access_token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Could not retrieve GitHub access token.",
        )

    try:
        repos = await github_service.list_repos(access_token)
    except Exception as exc:
        logger.warning("Failed to list GitHub repos for user %s: %s", current_user.id, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to retrieve repositories from GitHub.",
        )

    return repos


# --------------------------------------------------------------------------- #
# Repository deletion
# --------------------------------------------------------------------------- #

@router.delete("/repositories/{repo_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_repository(
    repo_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    repo = (
        db.query(Repository)
        .join(Project, Repository.project_id == Project.id)
        .filter(
            Repository.id == str(repo_id),
            Project.owner_id == current_user.id,
        )
        .first()
    )
    if not repo:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found.")
    db.delete(repo)
    db.flush()
