from unittest.mock import Mock

from runtime_host.app.reconciliation import reconcile_orphaned_jobs
from runtime_host.app.jobs import JobStore
from runtime_host.app.executor import DockerExecutor
from runtime_host.app.schemas import JobCancelResponse


def test_reconciliation_cleans_stale_job_resources():
    store = Mock()
    store.list_orphans.return_value = [
        {"job_id": "job-1", "assessment_id": "assessment-123456"}
    ]
    executor = Mock()
    executor.submit_cleanup.return_value = JobCancelResponse(
        job_id="job-1", status="CANCELLED", message="Cleanup completed"
    )

    assert reconcile_orphaned_jobs(store, executor) == 1
    store.update_status.assert_any_call(
        job_id="job-1",
        status="FAILED",
        error="Job was interrupted and reconciled during Runtime Host startup",
    )
    store.update_status.assert_called_with(job_id="job-1", status="CLEANED_UP")
    executor.submit_cleanup.assert_called_once_with(
        job_id="job-1",
        container_name="sentinelx-cont-assessment-1",
        network_name="sentinelx-net-assessment-1",
        image_tag="sentinelx-app-assessment-1",
    )


def test_reconciliation_leaves_failed_cleanup_marked_failed():
    store = Mock()
    store.list_orphans.return_value = [
        {"job_id": "job-1", "assessment_id": "assessment-123456"}
    ]
    executor = Mock()
    executor.submit_cleanup.return_value = JobCancelResponse(
        job_id="job-1", status="FAILED", message="Docker unavailable"
    )

    assert reconcile_orphaned_jobs(store, executor) == 0
    store.update_status.assert_called_once()


def test_job_store_filters_orphans_by_age(tmp_path):
    store = JobStore(str(tmp_path / "jobs.db"))
    store.create_job(
        job_id="job-old",
        idempotency_key="key-old",
        tenant_id="tenant",
        assessment_id="assessment",
        operation="build",
        resources=[],
        resource_limits={},
    )
    with store._get_conn() as conn:
        conn.execute(
            "UPDATE jobs SET updated_at = '2000-01-01T00:00:00+00:00' WHERE job_id = ?",
            ("job-old",),
        )
    assert [job["job_id"] for job in store.list_orphans(older_than_seconds=60)] == ["job-old"]


def test_cleanup_does_not_report_success_when_docker_fails(monkeypatch):
    executor = DockerExecutor()
    monkeypatch.setattr(
        executor,
        "_run_docker",
        lambda *_args, **_kwargs: (False, "Docker daemon unavailable"),
    )

    result = executor.submit_cleanup(
        job_id="job-1",
        container_name="sentinelx-cont-assessment",
        network_name="sentinelx-net-assessment",
        image_tag="sentinelx-app-assessment",
    )
    assert result.status == "FAILED"
    assert "Docker daemon unavailable" in result.message
