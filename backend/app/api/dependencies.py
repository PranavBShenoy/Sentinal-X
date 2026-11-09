"""
FastAPI dependency functions for SENTINEL-X.

Provides:
- DB session injection
- JWT authentication & user retrieval
- Resource-level ownership checks (project, assessment)
- Simple in-memory rate limiter for auth endpoints
"""
from __future__ import annotations

import logging
from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.rate_limiter import limiter as limiter, rate_limit as rate_limit
from app.core.security import decode_access_token
from app.models.models import Assessment, Project, User

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")




# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Decode the JWT, look up the user, and verify they are active.

    Raises HTTP 401 on invalid/expired tokens or missing/inactive users.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_access_token(token)
        user_id: Optional[str] = payload.get("sub")
        if not user_id:
            raise credentials_exception
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InvalidTokenError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled.",
        )
    return user


# ---------------------------------------------------------------------------
# Resource ownership checks
# ---------------------------------------------------------------------------


def get_project_or_404(
    project_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Project:
    """
    Return the project if it exists and belongs to the current user.

    - Raises 404 if the project does not exist.
    - Raises 403 if the project belongs to a different user.
    """
    project = db.query(Project).filter(Project.id == str(project_id)).first()
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    return project


def get_assessment_or_404(
    assessment_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Assessment:
    """
    Return the assessment if it exists and belongs to the current user's project.

    - Raises 404 if the assessment does not exist.
    - Raises 403 if the assessment's project belongs to a different user.
    """
    assessment = (
        db.query(Assessment)
        .join(Project, Assessment.project_id == Project.id)
        .filter(Assessment.id == str(assessment_id))
        .first()
    )
    if assessment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found.")
    if assessment.project.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    return assessment
