"""
Unit tests for Finding disposition updates and triage status alignment.
"""
import pytest
from app.models import (
    Assessment,
    AssessmentStatus,
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
)


@pytest.fixture
def test_assessment(db, test_project, test_repo, test_user):
    assessment = Assessment(
        project_id=test_project.id,
        repository_id=test_repo.id,
        created_by_id=test_user.id,
        status=AssessmentStatus.COMPLETED,
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return assessment


@pytest.fixture
def sample_finding(db, test_assessment):
    finding = Finding(
        assessment_id=test_assessment.id,
        title="SQL Injection Vulnerability",
        description="Unsanitized user input in query",
        category=FindingCategory.SAST,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        source_tool="semgrep",
        rule_id="python.lang.security.audit.sqli",
        file_path="app/db.py",
        line_start=42,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def test_update_disposition_false_positive(client, auth_headers, sample_finding):
    """Test updating disposition to FALSE_POSITIVE via PATCH."""
    res = client.patch(
        f"/api/v1/findings/{sample_finding.id}/disposition",
        json={"status": "FALSE_POSITIVE", "notes": "Test environment false positive"},
        headers=auth_headers,
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "FALSE_POSITIVE"
    assert data["suppression_reason"] == "Test environment false positive"
    assert data["suppressed_at"] is not None


def test_update_disposition_accepted_risk(client, auth_headers, sample_finding):
    """Test updating disposition to ACCEPTED_RISK via PUT."""
    res = client.put(
        f"/api/v1/findings/{sample_finding.id}",
        json={"status": "ACCEPTED_RISK", "suppression_reason": "Risk accepted by sec team"},
        headers=auth_headers,
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "ACCEPTED_RISK"
    assert data["suppression_reason"] == "Risk accepted by sec team"
    assert data["suppressed_at"] is not None


def test_update_disposition_suspected_alias_maps_to_open(client, auth_headers, sample_finding):
    """Test that frontend alias SUSPECTED maps to OPEN in backend."""
    res = client.patch(
        f"/api/v1/findings/{sample_finding.id}/disposition",
        json={"status": "SUSPECTED", "notes": "Under review"},
        headers=auth_headers,
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "OPEN"


def test_update_disposition_mitigated_alias_maps_to_fixed(client, auth_headers, sample_finding):
    """Test that frontend alias MITIGATED maps to FIXED in backend."""
    res = client.patch(
        f"/api/v1/findings/{sample_finding.id}/disposition",
        json={"status": "MITIGATED", "notes": "Hotfix deployed"},
        headers=auth_headers,
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "FIXED"


def test_update_disposition_suppressed(client, auth_headers, sample_finding):
    """Test updating disposition to SUPPRESSED."""
    res = client.patch(
        f"/api/v1/findings/{sample_finding.id}/disposition",
        json={"status": "SUPPRESSED", "notes": "Muted for 30 days"},
        headers=auth_headers,
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "SUPPRESSED"
    assert data["suppression_reason"] == "Muted for 30 days"


def test_update_disposition_unauthorized(client, auth_headers_2, sample_finding):
    """User 2 must not be able to update User 1's finding."""
    res = client.patch(
        f"/api/v1/findings/{sample_finding.id}/disposition",
        json={"status": "FALSE_POSITIVE", "notes": "Unauthorized attempt"},
        headers=auth_headers_2,
    )
    assert res.status_code == 404


def test_list_findings_filter_by_status(client, auth_headers, sample_finding, test_assessment, db):
    """Test filtering findings by status, including aliases."""
    # Create a second finding marked as FALSE_POSITIVE
    fp_finding = Finding(
        assessment_id=test_assessment.id,
        title="Benign Test Token",
        category=FindingCategory.SECRET,
        severity=FindingSeverity.LOW,
        status=FindingStatus.FALSE_POSITIVE,
        source_tool="gitleaks",
    )
    db.add(fp_finding)
    db.commit()

    # Filter by FALSE_POSITIVE
    res_fp = client.get(
        f"/api/v1/findings?assessment_id={test_assessment.id}&status=FALSE_POSITIVE",
        headers=auth_headers,
    )
    assert res_fp.status_code == 200
    data_fp = res_fp.json()
    assert data_fp["total"] == 1
    assert data_fp["items"][0]["status"] == "FALSE_POSITIVE"

    # Filter by OPEN
    res_open = client.get(
        f"/api/v1/findings?assessment_id={test_assessment.id}&status=OPEN",
        headers=auth_headers,
    )
    assert res_open.status_code == 200
    data_open = res_open.json()
    assert data_open["total"] == 1
    assert data_open["items"][0]["status"] == "OPEN"

    # Filter by SUSPECTED alias (should map to OPEN)
    res_suspected = client.get(
        f"/api/v1/findings?assessment_id={test_assessment.id}&status=SUSPECTED",
        headers=auth_headers,
    )
    assert res_suspected.status_code == 200
    data_suspected = res_suspected.json()
    assert data_suspected["total"] == 1
    assert data_suspected["items"][0]["status"] == "OPEN"


def test_generate_remediation_proposal_endpoint(client, auth_headers, sample_finding):
    """Test generating AI / deterministic remediation proposal for a finding."""
    res = client.post(
        f"/api/v1/findings/{sample_finding.id}/remediate",
        headers=auth_headers,
    )
    assert res.status_code == 201, res.text
    data = res.json()
    assert data["finding_id"] == str(sample_finding.id)
    assert "generation_mode" in data
    assert data["remediation_steps"] is not None or data["summary"] is not None


def test_get_finding_remediation_endpoint(client, auth_headers, sample_finding):
    """Test retrieving existing remediation proposal for a finding."""
    # Before creation, should return None/200
    res_before = client.get(
        f"/api/v1/findings/{sample_finding.id}/remediation",
        headers=auth_headers,
    )
    assert res_before.status_code == 200
    assert res_before.json() is None

    # Generate proposal
    client.post(
        f"/api/v1/findings/{sample_finding.id}/remediate",
        headers=auth_headers,
    )

    # After creation, should return the proposal
    res_after = client.get(
        f"/api/v1/findings/{sample_finding.id}/remediation",
        headers=auth_headers,
    )
    assert res_after.status_code == 200
    data = res_after.json()
    assert data is not None
    assert data["finding_id"] == str(sample_finding.id)


def test_finding_response_includes_raw_evidence_and_snippet(client, auth_headers, test_assessment, db):
    """Verify that raw_evidence and code_snippet are returned in FindingResponse."""
    finding = Finding(
        assessment_id=test_assessment.id,
        title="Custom Header & Snippet Test",
        category=FindingCategory.SAST,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        source_tool="semgrep",
        file_path="app/test.py",
        line_start=42,
        code_snippet="def vulnerable_func(): pass",
        raw_evidence={"rule": "test-rule", "extra": {"message": "Test message"}},
    )
    db.add(finding)
    db.commit()

    res = client.get(f"/api/v1/findings/{finding.id}", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["code_snippet"] == "def vulnerable_func(): pass"
    assert data["raw_evidence"] == {"rule": "test-rule", "extra": {"message": "Test message"}}


