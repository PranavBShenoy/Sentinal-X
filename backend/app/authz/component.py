"""
Authorization Component for SENTINEL-X.

Issues asymmetric job capability tokens after verifying assessment ownership
and tenant isolation from trusted database records. The private signing key
is held ONLY by this component and is never distributed to workers, the API,
or the Runtime Host.

Security properties:
- Private signing key never leaves this component
- Tenant and assessment ownership verified from DB before token issuance
- Worker-supplied tenant_id is NEVER trusted; DB record is authoritative
- Resource names derived from assessment_id, not client-supplied
- Short-lived mutation tokens (5 min TTL) for one-time operations
- Read tokens (15 min TTL) for status/logs polling

Note: The existing database schema has Assessment (linked to Project via
project_id) but no Tenant or Worker tables yet. The AuthorizationComponent
accepts an optional ownership_verifier callable for custom DB-backed checks.
When none is provided, it verifies assessment existence and ownership via
the existing Assessment/Project models.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Callable, Dict, List, Optional

from app.core.config import get_settings
from app.core.database import db_session
from app.models import Assessment, Project, Worker
from app.runtime.job_token import (
    generate_ed25519_keypair,
    sign_job_token,
    serialize_public_key,
)

settings = get_settings()
logger = logging.getLogger(__name__)

# Type for a custom ownership verification callback.
# Signature: (assessment_id: str, claimed_tenant_id: str, session) -> Optional[str]
# Returns the verified tenant_id from DB, or None if not authorized.
OwnershipVerifier = Callable[[str, str, Any], Optional[str]]


def _default_ownership_verifier(
    assessment_id: str,
    claimed_tenant_id: str,
    session: Any,
) -> Optional[str]:
    """Default DB-backed ownership verification using existing models.

    Verifies:
    1. Assessment exists
    2. Assessment's project owner matches the claimed tenant (derived from
       Project.owner_id, which is the authoritative tenant identifier)
    3. Worker is active and not revoked (must query Worker model from DB)
    4. Worker's user_id matches the assessment's created_by_user via Project
       ownership chain
    5. Assessment is in a non-terminal state

    Never trusts the caller-supplied tenant_id; returns the DB-authoritative
    value or None. Worker-supplied tenant IDs cannot override the trusted
    authorization context from DB records.
    """
    assessment = (
        session.query(Assessment)
        .filter(Assessment.id == assessment_id)
        .first()
    )
    if not assessment:
        logger.warning("Assessment not found: %s", assessment_id)
        return None

    # Load project to verify ownership chain
    project = (
        session.query(Project)
        .filter(Project.id == assessment.project_id)
        .first()
    )
    if not project:
        logger.warning(
            "Assessment has no project: %s", assessment_id
        )
        return None

    # DB-authoritative tenant: project owner_id
    verified_tenant_id = str(project.owner_id)

    # Never trust caller-supplied tenant_id; require DB match
    if verified_tenant_id != claimed_tenant_id:
        logger.warning(
            "Tenant mismatch: caller supplied %s, DB record says %s",
            claimed_tenant_id,
            verified_tenant_id,
        )
        return None

    # Verify Worker is active and not revoked, and belongs to the tenant.
    # The Worker model has user_id -> User -> Project -> Assessment ownership chain.
    # We check that the Worker's user_id matches the assessment's created_by_user.
    worker = session.query(Worker).filter(
        Worker.user_id == assessment.created_by_id
    ).first()
    if not worker:
        logger.warning(
            "Worker not found for assessment creator user %s",
            assessment.created_by_id,
        )
        return None

    if not worker.is_active:
        logger.warning(
            "Worker is inactive for assessment %s", assessment_id
        )
        return None

    if worker.is_revoked:
        logger.warning(
            "Worker is revoked for assessment %s", assessment_id
        )
        return None

    # Reject terminal states for mutation operations
    terminal = {"COMPLETED", "FAILED", "CANCELLED", "PARTIAL"}
    if assessment.status in terminal:
        logger.warning(
            "Assessment in terminal state: %s", assessment.status
            if hasattr(assessment.status, "value")
            else str(assessment.status),
        )
        return None

    return verified_tenant_id


class AuthorizationComponent:
    """Issues job capability tokens after DB-backed authorization checks.

    The private signing key is held only by this component. Workers and the
    API request tokens via HTTPS; the Runtime Host verifies them with the
    public key only.
    """

    def __init__(
        self,
        private_key_pem: Optional[bytes] = None,
        public_key_pem: Optional[bytes] = None,
        ownership_verifier: Optional[OwnershipVerifier] = None,
    ) -> None:
        """Initialize with optional pre-loaded keys and ownership verifier.

        If no keys are provided, a new Ed25519 pair is generated (development
        only; production should load from secure storage/HSM).

        If no ownership_verifier is provided, the default verifier checks
        Assessment/Project ownership via the existing database schema.
        """
        if private_key_pem and public_key_pem:
            from cryptography.hazmat.primitives import serialization

            self._private_key = serialization.load_pem_private_key(
                private_key_pem, password=None
            )
            self._public_key = serialization.load_pem_public_key(public_key_pem)
        else:
            self._private_key, self._public_key = generate_ed25519_keypair()
            logger.warning(
                "AuthorizationComponent generated ephemeral Ed25519 keys. "
                "Production must load keys from secure storage/HSM."
            )

        self._ownership_verifier = ownership_verifier or _default_ownership_verifier

    @property
    def public_key_pem(self) -> bytes:
        """Return the public verification key as PEM bytes for distribution
        to Runtime Hosts."""
        return serialize_public_key(self._public_key)

    def _verify_ownership(
        self,
        session: Any,
        assessment_id: str,
        claimed_tenant_id: str,
    ) -> Optional[str]:
        """Run the ownership verifier within a DB session.

        Returns the DB-authoritative tenant_id or None if not authorized.
        """
        try:
            return self._ownership_verifier(
                assessment_id, claimed_tenant_id, session
            )
        except Exception as exc:
            logger.exception(
                "Ownership verification raised an exception",
                assessment_id=assessment_id,
                error=str(exc),
            )
            return None

    def _derive_resources(self, assessment_id: str) -> List[str]:
        """Derive exact resource names from assessment_id.

        Resource names are generated by the Authorization Component, never
        supplied by the client. This prevents a compromised worker from
        requesting arbitrary container/network/image names.
        """
        short = assessment_id[:12]
        return [
            f"sentinelx-cont-{short}",
            f"sentinelx-app-{short}",
            f"sentinelx-net-{short}",
        ]

    def issue_mutation_token(
        self,
        *,
        assessment_id: str,
        tenant_id: str,
        operation: str,
        worker_cert_subject: str,
        resource_limits: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 300,
        audience: Optional[str] = None,
        jti: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> str:
        """Issue a one-time mutation capability token.

        Verifies:
        - Assessment ownership from DB (assessment belongs to tenant)
        - Assessment state permits the operation (non-terminal)
        - Worker cert subject is recorded for audit

        The caller-supplied tenant_id is never trusted; the DB-authoritative
        value is used in the token.

        Args:
            assessment_id: Owning assessment ID.
            tenant_id: Claimed owning tenant ID (verified against DB).
            operation: One of build, run, cleanup, cancel.
            worker_cert_subject: Subject of the worker's mTLS client cert
                (recorded for audit only).
            resource_limits: Resource limits for this job.
            ttl_seconds: Token lifetime (default 5 minutes).
            audience: Intended runtime host identifier (aud claim).
            jti: Unique job ID (auto-generated if not provided).
            job_id: Unique job identifier (auto-generated if not provided).

        Returns:
            Signed JWT capability token string.

        Raises:
            ValueError: If authorization checks fail.
        """
        with db_session() as session:
            verified_tenant_id = self._verify_ownership(
                session, assessment_id, tenant_id
            )
            if not verified_tenant_id:
                raise ValueError(
                    f"Assessment {assessment_id} not found or not owned by "
                    f"tenant {tenant_id}"
                )

        resources = self._derive_resources(assessment_id)
        token_jti = jti or str(uuid.uuid4())
        token_job_id = job_id or str(uuid.uuid4())

        token = sign_job_token(
            self._private_key,
            jti=token_jti,
            tenant_id=verified_tenant_id,
            assessment_id=assessment_id,
            job_id=token_job_id,
            operation=operation,
            resources=resources,
            resource_limits=resource_limits or {},
            token_type="mutation",
            ttl_seconds=ttl_seconds,
            audience=audience,
        )

        logger.info(
            "Mutation token issued",
            extra={
                "job_id": token_job_id,
                "assessment_id": assessment_id,
                "tenant_id": verified_tenant_id,
                "operation": operation,
                "worker_cert_subject": worker_cert_subject,
            },
        )
        return token

    def issue_read_token(
        self,
        *,
        assessment_id: str,
        tenant_id: str,
        operation: str,
        worker_cert_subject: str,
        resource_limits: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 900,
        audience: Optional[str] = None,
        jti: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> str:
        """Issue a re-usable read capability token for status/logs polling.

        Read tokens are not one-time-use but still bind to tenant, assessment,
        and operation for cross-tenant protection.

        Args:
            Same as issue_mutation_token, with read-only operation types.
        """
        with db_session() as session:
            verified_tenant_id = self._verify_ownership(
                session, assessment_id, tenant_id
            )
            if not verified_tenant_id:
                raise ValueError(
                    f"Assessment {assessment_id} not found or not owned by "
                    f"tenant {tenant_id}"
                )

        resources = self._derive_resources(assessment_id)
        token_jti = jti or str(uuid.uuid4())
        token_job_id = job_id or str(uuid.uuid4())

        token = sign_job_token(
            self._private_key,
            jti=token_jti,
            tenant_id=verified_tenant_id,
            assessment_id=assessment_id,
            job_id=token_job_id,
            operation=operation,
            resources=resources,
            resource_limits=resource_limits or {},
            token_type="read",
            ttl_seconds=ttl_seconds,
            audience=audience,
        )

        logger.info(
            "Read token issued",
            extra={
                "job_id": token_job_id,
                "assessment_id": assessment_id,
                "tenant_id": verified_tenant_id,
                "operation": operation,
                "worker_cert_subject": worker_cert_subject,
            },
        )
        return token
