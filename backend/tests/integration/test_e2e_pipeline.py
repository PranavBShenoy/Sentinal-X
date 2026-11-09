import os
from pathlib import Path
import pytest
from app.models import (
    User,
    Project,
    Repository,
    Assessment,
    AssessmentStatus,
    ScanJob,
    Report,
)
from app.services.assessment_pipeline import AssessmentPipeline


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

    # Execute pipeline
    pipeline = AssessmentPipeline(str(assessment.id))
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
