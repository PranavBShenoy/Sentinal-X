
import pytest
import os
import uuid
from pathlib import Path
from app.models import (
    Project,
    Repository,
    Assessment,
    AssessmentStatus,
    ScanJob,
    Report,
)
from app.services.assessment_pipeline import AssessmentPipeline


@pytest.mark.skip(reason='AnyIO portal deadlock in test environment')
def test_end_to_end_pipeline_execution(client, test_user, db):
    # Locate vuln_sqli fixture
    fixture_dir = Path(__file__).resolve().parent.parent.parent.parent / "tests" / "fixtures" / "vuln_sqli"
    assert fixture_dir.exists(), f"Fixture dir {fixture_dir} does not exist"

    # Create project and repository pointing to fixture_dir
    project = Project(
        name="E2E Vulnerable SQLi Test",
        owner_id=test_user.id,
    )
    db.add(project)
    db.flush()

    repo = Repository(
        project_id=project.id,
        full_name="tests/vuln_sqli",
        clone_url=str(fixture_dir),
        default_branch="main",
    )
    db.add(repo)
    db.flush()

    assessment = Assessment(
        project_id=project.id,
        repository_id=repo.id,
        created_by_id=test_user.id,
        branch="main",
        status=AssessmentStatus.CREATED,
    )
    db.add(assessment)
    db.commit()

    # Create durable authorization record for task provenance
    from app.models import AuthorizationRequest
    import uuid
    request_id = str(uuid.uuid4())
    auth_record = AuthorizationRequest(
        user_id=str(test_user.id),
        assessment_id=str(assessment.id),
        tenant_id=str(project.owner_id),
        operation="provision",
        request_id=request_id,
        status="pending",
    )
    db.add(auth_record)
    db.commit()

    # Atomically consume the AuthorizationRecord (simulating Celery task behavior)
    from sqlalchemy import text
    from app.core.database import engine, SessionLocal
    session = SessionLocal()
    # Use SQLite-compatible datetime function
    result = session.execute(
        text(
            "UPDATE authorization_requests "
            "SET status = 'consumed', "
            "consumed_at = CURRENT_TIMESTAMP "
            "WHERE request_id = :request_id "
            "AND status = 'pending'"
        ),
        {"request_id": request_id},
    )
    session.commit()
    affected_rows = result.rowcount
    session.close()
    if affected_rows != 1:
        raise ValueError(f"Failed to consume authorization record: expected 1 affected row, got {affected_rows}")

    # Execute pipeline
    pipeline = AssessmentPipeline(str(assessment.id), request_id)
    result = pipeline.execute()

    assert result is not None
    assert result["assessment_id"] == str(assessment.id)
    assert result["status"] in (AssessmentStatus.COMPLETED.value, AssessmentStatus.PARTIAL.value)

    # Verify database state
    db.refresh(assessment)
    assert assessment.status in (AssessmentStatus.COMPLETED, AssessmentStatus.PARTIAL)
    assert assessment.repo_analysis is not None
    assert assessment.repo_analysis.get("project_type") in ("fastapi", "python")

    # Verify scan jobs were recorded
    jobs = db.query(ScanJob).filter(ScanJob.assessment_id == str(assessment.id)).all()
    assert len(jobs) > 0
    job_tools = {j.tool_name for j in jobs}
    # Semgrep, Gitleaks, Syft, Grype, etc. should have recorded jobs
    assert "semgrep" in job_tools or "gitleaks" in job_tools

    # Verify reports were generated
    reports = db.query(Report).filter(Report.assessment_id == str(assessment.id)).all()
    assert len(reports) >= 2  # json and sarif
    report_formats = {r.format for r in reports}
    assert "json" in report_formats
    assert "sarif" in report_formats

    for r in reports:
        assert os.path.exists(r.file_path)
