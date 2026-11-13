"""
Assessment pipeline orchestration tasks.

Each Celery task corresponds to one stage of the assessment pipeline.
Tasks are designed to be:
- Idempotent where possible
- Independently retryable on transient failures
- Self-contained with proper cleanup in finally blocks
- Security-conscious: no secrets in logs, no shell string interpolation

Pipeline stages:
  CREATED → REPOSITORY_FETCH → REPOSITORY_ANALYSIS → STATIC_SCANS →
  SBOM_GENERATION → DEPENDENCY_ANALYSIS → RUNTIME_PROVISIONING →
  DYNAMIC_TESTING → FINDING_NORMALIZATION → CORRELATION_AND_RISK →
  AI_ANALYSIS → REPORT_GENERATION → COMPLETED/PARTIAL/FAILED
"""
from __future__ import annotations

from typing import Optional

from celery.utils.log import get_task_logger
from sqlalchemy import func

from app.core.config import get_settings
from app.core.database import db_session, SessionLocal
from app.workers.celery_app import celery_app
from app.models import (
    Assessment,
    AssessmentStatus,
    AuthorizationRequest,
    Project,
    RuntimeStatus,
    User,
    Worker,
)

settings = get_settings()
logger = get_task_logger(__name__)


def _get_db_session():
    """Get a database session using the application's configured SessionLocal.
    Never create a fresh sqlite:///:memory: engine — always use the authoritative
    database bound to SessionLocal (PostgreSQL in production, SQLite for testing).
    """
    return SessionLocal()


def _update_assessment_status(
    assessment_id: str,
    status: str,
    stage: Optional[str] = None,
    error: Optional[str] = None,
) -> None:
    """Update assessment status in database."""
    with db_session() as db:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if assessment:
            try:
                assessment.status = AssessmentStatus(status)
            except ValueError:
                assessment.status = status
            if stage:
                assessment.current_stage = stage
            if error:
                assessment.error_message = error


def _get_user(session, user_id: str):
    """Reload user from DB and verify basic existence."""
    user = session.query(User).get(user_id)
    if not user:
        raise ValueError(f"User {user_id} not found in database; cannot verify authorization.")
    return user


def _get_assessment(session, assessment_id: str):
    """Reload assessment from DB."""
    assessment = session.query(Assessment).get(assessment_id)
    if not assessment:
        raise ValueError(f"Assessment {assessment_id} not found in database.")
    return assessment


def _get_project(session, assessment):
    """Reload project and verify ownership."""
    project = session.query(Project).get(assessment.project_id)
    if not project:
        raise ValueError(
            f"Assessment {assessment.id} has no associated project; cannot verify ownership."
        )
    return project


def _get_valid_authorization_request(session, assessment_id: str, user_id: str,
                                      tenant_id: str, operation: str = "provision"):
    """Reload and validate the durable AuthorizationRequest record.

    Verifies the request is bound to the correct user+assessment+tenant+operation,
    has status 'approved' and is not yet consumed, and returns the request_id
    to be passed to RuntimeOrchestrator.provision().

    AuthorizationRequest.tenant_id is verified against the project owner_id.
    AuthorizationRequest.operation is verified against the expected operation.
    Only 'approved' status is accepted; 'consumed' requests are handled
    via atomic consumption in provision_runtime().
    """
    auth_request = (
        session.query(AuthorizationRequest)
        .filter(AuthorizationRequest.assessment_id == assessment_id)
        .filter(AuthorizationRequest.user_id == user_id)
        .filter(AuthorizationRequest.tenant_id == tenant_id)
        .filter(AuthorizationRequest.operation == operation)
        .filter(AuthorizationRequest.status == "approved")
        .first()
    )
    if not auth_request:
        raise ValueError(
            f"No valid authorization request found for assessment {assessment_id}, "
            f"user {user_id}, tenant {tenant_id}, operation {operation}.  "
            f"Status must be 'approved'."
        )
    return auth_request.request_id


def _get_active_worker(session, user_id: str):
    """Reload worker bound to the user; verify active and not revoked."""
    worker = session.query(Worker).filter(Worker.user_id == user_id).first()
    if not worker:
        raise ValueError(
            f"No worker found for user {user_id}; "
            f"cannot issue job capability token for runtime provisioning."
        )
    if not worker.is_active:
        raise ValueError(
            f"Worker for user {user_id} is inactive; "
            f"cannot issue job capability token for runtime provisioning."
        )
    if worker.is_revoked:
        raise ValueError(
            f"Worker for user {user_id} is revoked; "
            f"cannot issue job capability token for runtime provisioning."
        )
    return worker


def _consume_authorization_request(session, assessment_id: str, request_id: str) -> None:
    """Atomically validate and consume a pending/approved authorization request.

    Enforces provenance (request bound to the assessment and ``provision``
    operation) and single consumption.  Raises ``ValueError`` if the request
    is missing, already consumed, or cannot be claimed.
    """
    from sqlalchemy import func

    auth_request = (
        session.query(AuthorizationRequest)
        .filter(AuthorizationRequest.request_id == request_id)
        .filter(AuthorizationRequest.assessment_id == assessment_id)
        .filter(AuthorizationRequest.operation == "provision")
        .first()
    )
    if not auth_request:
        raise ValueError(
            f"No authorization request found for assessment {assessment_id} "
            f"and request_id {request_id}."
        )
    if auth_request.status == "consumed":
        raise ValueError(
            f"Authorization request {request_id} was already consumed; "
            f"refusing duplicate execution."
        )
    if auth_request.status not in ("pending", "approved"):
        raise ValueError(
            f"Authorization request {request_id} has status "
            f"'{auth_request.status}'; cannot execute."
        )

    updated = (
        session.query(AuthorizationRequest)
        .filter(AuthorizationRequest.request_id == request_id)
        .filter(AuthorizationRequest.status.in_(("pending", "approved")))
        .update(
            {"status": "consumed", "consumed_at": func.now()},
            synchronize_session="fetch",
        )
    )
    if updated != 1:
        raise ValueError(
            f"Authorization request {request_id} could not be atomically "
            f"consumed (concurrent delivery detected)."
        )
    session.flush()


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.run_assessment",
)
def run_assessment(self, assessment_id: str, request_id: str = None) -> dict:
    """Validate authorization, consume it exactly once, then run the pipeline."""
    if not request_id:
        raise ValueError(
            "Authorization request_id is required to run an assessment."
        )

    session = _get_db_session()
    try:
        _consume_authorization_request(session, assessment_id, request_id)
        session.commit()
    except Exception:
        session.rollback()
        logger.error(
            "Assessment authorization validation failed for assessment %s",
            assessment_id,
        )
        raise
    finally:
        session.close()

    from app.services.assessment_pipeline import AssessmentPipeline
    from app.authz.dependencies import get_authorization_component

    authz_component = (
        get_authorization_component() if settings.RUNTIME_MODE == "remote" else None
    )
    return AssessmentPipeline(
        assessment_id,
        request_id=request_id,
        authz_component=authz_component,
    ).execute()


def provision_runtime(self, assessment_id: str, workspace_path: str, user_id: str = None) -> dict:
    """Attempt to build and start the application in an isolated environment.

    Enforces database-backed authorization using the application's configured
    SQLAlchemy database (not a per-call sqlite:///:memory: ephemeral store).

    Authorization flow:
    1. Reload User from DB — must exist and be active
    2. Reload Assessment from DB — must exist and be owned by user's project
    3. Validate durable AuthorizationRequest — must be 'approved', properly
       bound (tenant_id, operation), and not yet consumed
    4. Validate Worker — must exist, be active, and not revoked
    5. Atomically claim execution ownership — one Execution per
       AuthorizationRequest.  Duplicate deliveries detect the existing
       execution and return its state or safely resume without launching
       another container/job.
    6. Authorization complete; proceed with orchestration via provision()

    Authorization fails closed: any missing/invalid check raises ValueError.
    The validated and consumed request_id is passed to
    RuntimeOrchestrator.provision() which enforces its own mandatory
    request_id validation (requires status='consumed'.

    Execution idempotency:
    - An INSERT ... ON CONFLICT (authorization_request_id) atomically claims
      ownership.  Only the task that inserts the record may proceed to
      provision(); concurrent tasks detect the existing record and inspect
      its status.
    -  A completed execution returns its result; a failed or running
      execution prevents a duplicate launch.
    -  Crash recovery: if the AuthorizationRequest is consumed but no
      Execution exists (crash between steps 5 and 7), a retry may create a
      new Execution and resume.  If an Execution exists with status='running',
      the task must not launch a second container.
    -  The execution record is the single source of truth for ownership; the
      deterministic UUID is no longer the sole concurrency lock.
    """
    from uuid import uuid4

    from app.models import Execution
    from app.models.enums import ExecutionStatus

    session = _get_db_session()

    try:
        # 1. Reload user from DB and verify active
        user = _get_user(session, user_id)
        if not user.is_active:
            raise ValueError(f"User {user.id} is inactive; cannot initiate runtime provisioning.")

        # 2. Reload assessment and verify ownership
        assessment = _get_assessment(session, assessment_id)

        project = _get_project(session, assessment)

        if project.owner_id != user.id:
            raise ValueError(
                f"User {user.id} is not the owner of project {project.id}; "
                f"cannot authorize assessment {assessment.id} provisioning. "
                f"Project owner is {project.owner_id}."
            )

        # 3. Validate durable AuthorizationRequest — provenance boundary.
        #    Verifies user_id, assessment_id, tenant_id, operation, and status='approved'.
        #    Also retrieve the AuthorizationRequest's primary key for the Execution FK.
        # Tenant identity comes from the project record, never a caller-supplied value.
        tenant_id = str(project.owner_id)
        operation = "provision"
        auth_request = (
            session.query(AuthorizationRequest)
            .filter(AuthorizationRequest.assessment_id == assessment_id)
            .filter(AuthorizationRequest.user_id == user_id)
            .filter(AuthorizationRequest.tenant_id == tenant_id)
            .filter(AuthorizationRequest.operation == operation)
            .filter(AuthorizationRequest.status == "approved")
            .first()
        )
        if not auth_request:
            raise ValueError(
                f"No valid authorization request found for assessment {assessment_id}, "
                f"user {user_id}, tenant {tenant_id}, operation {operation}.  "
                f"Status must be 'approved'."
            )
        request_id = auth_request.request_id
        ar_id = str(auth_request.id)  # PK used as FK by Execution model

        # 4. Verify the worker belongs to the authorized identity
        _get_active_worker(session, user.id)

        # 5. Atomically claim execution ownership.
        #    Try to insert a new Execution record bound to this
        #    AuthorizationRequest.  The unique constraint on
        #    authorization_request_id ensures only one task can claim it.
        #    ON CONFLICT causes the DB to return the existing record.
        existing_execution = session.query(Execution).filter(
            Execution.authorization_request_id == ar_id
        ).with_for_update(skip_locked=True).first()

        if existing_execution is None:
            # No execution exists yet — this task creates and claims it.
            execution_id = uuid4()
            new_execution = Execution(
                id=execution_id,
                authorization_request_id=ar_id,  # Use AR's PK, not request_id string
                status=ExecutionStatus.RUNNING,
                started_at=func.now(),
            )
            session.add(new_execution)
            session.flush()  # persist so we have the ID for the AR update
            existing_execution = new_execution
        else:
            # An execution already exists for this AuthorizationRequest.
            # Distinguish the cases.
            if existing_execution.status == ExecutionStatus.COMPLETED:
                # A previous execution completed successfully.  Return the
                # stored result rather than launching another container.
                # The result was stored by the previous task's finally path.
                raise ValueError(
                    f"Runtime already completed for authorization {request_id}; "
                    f"result: {existing_execution.result}"
                )
            if existing_execution.status == ExecutionStatus.FAILED:
                # A previous execution failed.  Do not launch a duplicate; raise
                # so the caller can decide whether to retry the overall assessment.
                raise ValueError(
                    f"Previous runtime execution failed for authorization {request_id}"
                )
            if existing_execution.status == ExecutionStatus.RUNNING:
                # Another task already claimed and is executing.  This is a
                # concurrent duplicate delivery — reject to avoid two containers.
                raise ValueError(
                    f"Runtime already running for authorization {request_id}; "
                    f"concurrent delivery detected."
                )
            if existing_execution.status == ExecutionStatus.PENDING:
                # Should not normally happen, but treat as a new claim.
                # Update status to running and proceed.
                existing_execution.status = ExecutionStatus.RUNNING
                existing_execution.started_at = func.now()
                session.flush()

        # 5b. Mark the AuthorizationRequest as consumed, binding the execution ID.
        #     This is safe now that execution ownership is tracked in the
        #     Executions table; the deterministic UUID is no longer the concurrency
        #     lock, but we still record it for observability.
        session.query(AuthorizationRequest).filter(
            AuthorizationRequest.request_id == request_id
        ).update({
            "status": "consumed",
            "consumed_at": func.now(),
            "execution_id": existing_execution.id if existing_execution else str(execution_id),
        }, synchronize_session='fetch')
        session.flush()

        # 6. Provision the runtime via the orchestrator.
        from app.runtime.docker.orchestrator import RuntimeOrchestrator
        from app.authz.dependencies import get_authorization_component
        authz_component = (
            get_authorization_component() if settings.RUNTIME_MODE == "remote" else None
        )
        orchestrator = RuntimeOrchestrator(authz_component=authz_component)
        provision_result = orchestrator.provision(assessment_id, workspace_path, request_id=request_id)

        # 7. Record the execution result and mark completion.
        #     We store a minimal result dict; the full container URL etc. come
        #     from the orchestrator's return value.
        existing_execution.result = {
            "target_url": provision_result.get("target_url"),
            "status": provision_result.get("status"),
        }
        if provision_result.get("status") in (RuntimeStatus.RUNNING.value, "running"):
            existing_execution.status = ExecutionStatus.COMPLETED
        else:
            existing_execution.status = ExecutionStatus.FAILED
        existing_execution.completed_at = func.now()
        session.flush()

        return provision_result

    except Exception:
        # If we own the execution and something goes wrong before completion,
        # mark the execution as failed so a subsequent retry can detect it.
        try:
            exec_id = session.query(Execution).filter(
                Execution.authorization_request_id == request_id
            ).with_for_update().first()
            if exec_id and exec_id.status != ExecutionStatus.COMPLETED:
                exec_id.status = ExecutionStatus.FAILED
                exec_id.completed_at = func.now()
                session.flush()
        except Exception:
            pass
        session.rollback()
        raise
    finally:
        session.close()


@celery_app.task(
    bind=True,
    name="app.workers.assessment_tasks.correlate_and_score",
)
def correlate_and_score(self, assessment_id: str) -> dict:
    """Correlate findings, build dependency graph, and compute risk scores."""
    from app.analysis.correlation.correlator import FindingCorrelator
    from app.analysis.dependency_graph.builder import DependencyGraphBuilder
    from app.analysis.risk.engine import RiskEngine

    # Build dependency graph
    graph_builder = DependencyGraphBuilder()
    graph_builder.build(assessment_id)

    # Correlate findings
    correlator = FindingCorrelator()
    correlator.correlate(assessment_id)

    # Score risks
    engine = RiskEngine()
    engine.score_all(assessment_id)

    return {"status": "completed"}
