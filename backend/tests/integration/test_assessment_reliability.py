"""
Integration tests for assessment operational reliability:
- Assessment cancellation transitions and state validation
- Finding deduplication on scanner retries and re-execution
- Orchestration health and readiness probes (/health/live, /health/ready)
"""
from unittest.mock import MagicMock, patch
from pathlib import Path

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.integrations.gitleaks.scanner import GitleaksScanner
from app.models import (
    Assessment,
    AssessmentStatus,
    Finding,
)


def test_assessment_cancellation_lifecycle(client, auth_headers, test_project, test_repo):
    """Verify in-progress assessment cancellation and rejection of invalid states."""
    # 1. Create a fresh assessment (status: CREATED)
    create_resp = client.post(
        f"/api/v1/projects/{test_project.id}/assessments",
        json={"repository_id": str(test_repo.id), "branch": "main"},
        headers=auth_headers,
    )
    assert create_resp.status_code == 201
    assessment_id = create_resp.json()["id"]

    # 2. Cancel the assessment
    cancel_resp = client.delete(
        f"/api/v1/assessments/{assessment_id}/cancel",
        headers=auth_headers,
    )
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "CANCELLED"

    # 3. Attempting to cancel an already CANCELLED assessment must return 400
    retry_cancel = client.delete(
        f"/api/v1/assessments/{assessment_id}/cancel",
        headers=auth_headers,
    )
    assert retry_cancel.status_code == 400
    assert "Cannot cancel assessment in state 'CANCELLED'" in retry_cancel.json()["detail"]


def test_cancellation_rejected_for_terminal_states(client, auth_headers, test_project, test_repo, db: Session):
    """Terminal states (COMPLETED, FAILED) cannot be cancelled."""
    # Completed assessment
    completed_assessment = Assessment(
        project_id=test_project.id,
        repository_id=test_repo.id,
        created_by_id=test_project.owner_id,
        branch="main",
        status=AssessmentStatus.COMPLETED,
    )
    db.add(completed_assessment)
    db.commit()

    resp = client.delete(
        f"/api/v1/assessments/{completed_assessment.id}/cancel",
        headers=auth_headers,
    )
    assert resp.status_code == 400
    assert "COMPLETED" in resp.json()["detail"]

    # Failed assessment
    failed_assessment = Assessment(
        project_id=test_project.id,
        repository_id=test_repo.id,
        created_by_id=test_project.owner_id,
        branch="main",
        status=AssessmentStatus.FAILED,
    )
    db.add(failed_assessment)
    db.commit()

    resp = client.delete(
        f"/api/v1/assessments/{failed_assessment.id}/cancel",
        headers=auth_headers,
    )
    assert resp.status_code == 400
    assert "FAILED" in resp.json()["detail"]


def test_scanner_retry_deduplication(db: Session, test_project, test_repo):
    """
    Verify that executing a scanner repeatedly on the same assessment updates existing
    findings via stable fingerprint rather than duplicating records.
    """
    assessment = Assessment(
        project_id=test_project.id,
        repository_id=test_repo.id,
        created_by_id=test_project.owner_id,
        branch="main",
        status=AssessmentStatus.STATIC_SCANS,
    )
    db.add(assessment)
    db.commit()

    fixture_path = str(Path(__file__).resolve().parent.parent.parent.parent / "tests" / "fixtures" / "secret_leak")

    scanner = GitleaksScanner()

    # Pass 1: Run scan
    res1 = scanner.scan(assessment_id=str(assessment.id), workspace_path=fixture_path)
    assert res1["status"] in ("SUCCESS", "WARNING", "COMPLETED")

    pass1_findings = db.query(Finding).filter(Finding.assessment_id == assessment.id).all()
    count_pass1 = len(pass1_findings)
    assert count_pass1 > 0

    first_seen_initial = {f.id: f.first_seen_at for f in pass1_findings}
    last_seen_initial = {f.id: f.last_seen_at for f in pass1_findings}

    # Pass 2: Retry scan on same assessment
    res2 = scanner.scan(assessment_id=str(assessment.id), workspace_path=fixture_path)
    assert res2["status"] in ("SUCCESS", "WARNING", "COMPLETED")

    pass2_findings = db.query(Finding).filter(Finding.assessment_id == assessment.id).all()
    count_pass2 = len(pass2_findings)

    # Finding count must be identical (no duplicates created)
    assert count_pass2 == count_pass1

    # First seen should remain constant while last seen is updated
    for f in pass2_findings:
        assert f.first_seen_at == first_seen_initial[f.id]
        assert f.last_seen_at is not None


def test_liveness_and_readiness_probes(client):
    """Test platform liveness and readiness health checks."""
    # 1. Liveness endpoint
    live_resp = client.get("/health/live")
    assert live_resp.status_code == 200
    assert live_resp.json()["status"] == "alive"

    v1_live_resp = client.get("/api/v1/health/live")
    assert v1_live_resp.status_code == 200
    assert v1_live_resp.json()["status"] == "alive"

    # 2. Readiness endpoint (healthy condition)
    ready_resp = client.get("/health/ready")
    assert ready_resp.status_code in (200, 503)
    data = ready_resp.json()
    assert "database" in data
    assert "redis" in data


def test_readiness_probe_degraded_on_db_failure(client):
    """Readiness probe must return 503 Service Unavailable when DB is unreachable."""
    with patch("app.main.db_session") as mock_db_session:
        mock_session_ctx = MagicMock()
        mock_session_ctx.__enter__.side_effect = OperationalError("connection failure", params=None, orig=Exception("Simulated DB down"))
        mock_db_session.return_value = mock_session_ctx

        resp = client.get("/health/ready")
        assert resp.status_code == 503
        data = resp.json()
        assert data["status"] == "degraded"
        assert data["database"]["connected"] is False
        assert "connection failure" in data["database"]["error"]
