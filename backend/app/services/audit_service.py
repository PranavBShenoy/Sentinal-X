"""
Audit logging service for SENTINEL-X.

Records security-sensitive actions to the immutable audit_logs table.
Secrets must NEVER appear in the `details` field.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.models import AuditLog

logger = logging.getLogger(__name__)


class AuditService:
    """Service for writing immutable audit log entries."""

    def log(
        self,
        db: Session,
        user_id: Optional[str],
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Create an AuditLog entry.

        Args:
            db:            Active database session.
            user_id:       ID of acting user (None for anonymous actions).
            action:        Human-readable action name, e.g. 'user.login'.
            resource_type: Entity type affected, e.g. 'assessment'.
            resource_id:   Entity ID string.
            ip_address:    Client IP address.
            user_agent:    Client User-Agent header.
            details:       Arbitrary safe metadata. MUST NOT contain secrets,
                           tokens, passwords, or encryption keys.
        """
        try:
            entry = AuditLog(
                user_id=str(user_id) if user_id else None,
                action=action,
                resource_type=resource_type,
                resource_id=str(resource_id) if resource_id else None,
                ip_address=ip_address,
                user_agent=user_agent[:500] if user_agent else None,
                details=details or {},
            )
            db.add(entry)
            db.flush()  # Write within current transaction without committing
        except Exception:
            # Audit failures must never crash the main request path.
            logger.exception("Failed to write audit log entry for action=%s", action)


# Module-level singleton — stateless, so sharing is safe.
audit_service = AuditService()
