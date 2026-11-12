"""
Durable job state store for the Runtime Host.

Uses SQLite (file-based) on the runtime host VM, separate from control-plane
databases. Provides CRUD operations for job state with idempotency support.

Job states: PENDING -> BUILDING -> RUNNING -> COMPLETED / FAILED / CANCELLED -> CLEANED_UP
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

_JOB_STATES = {
    "PENDING",
    "BUILDING",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
    "CLEANED_UP",
}

# Valid state transitions
_VALID_TRANSITIONS: dict[str, set[str]] = {
    "PENDING": {"BUILDING", "FAILED", "CANCELLED"},
    "BUILDING": {"RUNNING", "FAILED", "CANCELLED"},
    "RUNNING": {"COMPLETED", "FAILED", "CANCELLED"},
    "COMPLETED": {"CLEANED_UP"},
    "FAILED": {"CLEANED_UP"},
    "CANCELLED": {"CLEANED_UP"},
    "CLEANED_UP": set(),  # terminal
}


class JobStore:
    """Thread-safe SQLite job store with idempotency support."""

    def __init__(self, db_path: str | None = None) -> None:
        import os

        self.db_path = db_path or os.environ.get(
            "SENTINELX_JOB_STORE_PATH",
            os.path.expanduser("~/.local/share/sentinelx/runtime_host/jobs.db"),
        )
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        import os

        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    idempotency_key TEXT UNIQUE,
                    tenant_id TEXT NOT NULL,
                    assessment_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    resources TEXT NOT NULL DEFAULT '[]',
                    resource_limits TEXT NOT NULL DEFAULT '{}',
                    target_url TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_jobs_idempotency_key "
                "ON jobs(idempotency_key)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_jobs_assessment_id "
                "ON jobs(assessment_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_jobs_status ON jobs(status)"
            )
            conn.commit()

    def _validate_transition(
        self, current: str, new: str
    ) -> None:
        """Validate a state transition."""
        if new not in _VALID_TRANSITIONS.get(current, set()):
            raise ValueError(
                f"Invalid state transition: {current} -> {new}"
            )

    def create_job(
        self,
        *,
        job_id: str,
        idempotency_key: str,
        tenant_id: str,
        assessment_id: str,
        operation: str,
        resources: list[str],
        resource_limits: dict,
    ) -> bool:
        """Create a new job in PENDING state.

        Returns False if a job with the same idempotency_key already exists
        (idempotent submission).
        """
        import json

        now = datetime.now(UTC).isoformat()
        with self._lock, self._get_conn() as conn:
            # Check idempotency
            existing = conn.execute(
                "SELECT job_id FROM jobs WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if existing:
                return False  # Duplicate submission; return existing job

            try:
                conn.execute(
                    """
                        INSERT INTO jobs
                        (job_id, idempotency_key, tenant_id, assessment_id,
                         operation, status, resources, resource_limits,
                         created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                    (
                        job_id,
                        idempotency_key,
                        tenant_id,
                        assessment_id,
                        operation,
                        "PENDING",
                        json.dumps(resources),
                        json.dumps(resource_limits),
                        now,
                        now,
                    ),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                return False  # Duplicate job_id
            return True

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        """Get job state by job_id."""
        import json

        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if not row:
                return None
            return {
                "job_id": row["job_id"],
                "idempotency_key": row["idempotency_key"],
                "tenant_id": row["tenant_id"],
                "assessment_id": row["assessment_id"],
                "operation": row["operation"],
                "status": row["status"],
                "resources": json.loads(row["resources"]),
                "resource_limits": json.loads(row["resource_limits"]),
                "target_url": row["target_url"],
                "error": row["error"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "completed_at": row["completed_at"],
            }

    def get_job_by_idempotency_key(
        self, idempotency_key: str
    ) -> dict[str, Any] | None:
        """Get job state by idempotency key."""
        import json

        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM jobs WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if not row:
                return None
            return {
                "job_id": row["job_id"],
                "idempotency_key": row["idempotency_key"],
                "tenant_id": row["tenant_id"],
                "assessment_id": row["assessment_id"],
                "operation": row["operation"],
                "status": row["status"],
                "resources": json.loads(row["resources"]),
                "resource_limits": json.loads(row["resource_limits"]),
                "target_url": row["target_url"],
                "error": row["error"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "completed_at": row["completed_at"],
            }

    def update_status(
        self,
        *,
        job_id: str,
        status: str,
        target_url: str | None = None,
        error: str | None = None,
        completed_at: str | None = None,
    ) -> bool:
        """Update job status with transition validation.

        Returns False if the job doesn't exist or the transition is invalid.
        """

        now = datetime.now(UTC).isoformat()
        with self._lock, self._get_conn() as conn:
            row = conn.execute(
                "SELECT status FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if not row:
                return False

            current_status = row["status"]
            self._validate_transition(current_status, status)

            updates: list[str] = ["status = ?", "updated_at = ?"]
            params: list[Any] = [status, now]

            if target_url is not None:
                updates.append("target_url = ?")
                params.append(target_url)
            if error is not None:
                updates.append("error = ?")
                params.append(error)
            if completed_at is not None:
                updates.append("completed_at = ?")
                params.append(completed_at)
            elif status in ("COMPLETED", "FAILED", "CANCELLED"):
                updates.append("completed_at = ?")
                params.append(now)

            params.append(job_id)
            conn.execute(
                f"UPDATE jobs SET {', '.join(updates)} WHERE job_id = ?",  # noqa
                params,
            )
            conn.commit()
            return True

    def list_orphans(
        self, older_than_seconds: int = 3600
    ) -> list[dict[str, Any]]:
        """List jobs that may be orphaned (in non-terminal states for too long)."""
        cutoff = (datetime.now(UTC) - timedelta(seconds=older_than_seconds)).isoformat()
        non_terminal = ("PENDING", "BUILDING", "RUNNING")
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM jobs
                WHERE status IN (?, ?, ?)
                AND datetime(updated_at) < datetime(?)
                """,
                (*non_terminal, cutoff),
            ).fetchall()
            import json

            return [
                {
                    "job_id": row["job_id"],
                    "idempotency_key": row["idempotency_key"],
                    "tenant_id": row["tenant_id"],
                    "assessment_id": row["assessment_id"],
                    "operation": row["operation"],
                    "status": row["status"],
                    "resources": json.loads(row["resources"]),
                    "target_url": row["target_url"],
                    "error": row["error"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
                for row in rows
            ]
