"""Startup reconciliation for jobs interrupted by a Runtime Host restart."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def reconcile_orphaned_jobs(job_store, executor, older_than_seconds: int = 3600) -> int:
    """Fail stale jobs and remove their deterministic assessment resources."""
    reconciled = 0
    for orphan in job_store.list_orphans(older_than_seconds=older_than_seconds):
        job_id = orphan["job_id"]
        assessment_id = orphan["assessment_id"]
        try:
            job_store.update_status(
                job_id=job_id,
                status="FAILED",
                error="Job was interrupted and reconciled during Runtime Host startup",
            )
            result = executor.submit_cleanup(
                job_id=job_id,
                container_name=f"sentinelx-cont-{assessment_id[:12]}",
                network_name=f"sentinelx-net-{assessment_id[:12]}",
                image_tag=f"sentinelx-app-{assessment_id[:12]}",
            )
            if result.status == "CANCELLED":
                job_store.update_status(job_id=job_id, status="CLEANED_UP")
                reconciled += 1
            else:
                logger.error(
                    "Orphan resource cleanup failed",
                    extra={"job_id": job_id, "message": result.message},
                )
        except Exception:
            logger.exception(
                "Runtime Host orphan reconciliation failed",
                extra={"job_id": job_id},
            )
    return reconciled
