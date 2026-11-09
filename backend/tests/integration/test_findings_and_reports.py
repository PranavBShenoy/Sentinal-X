"""
Integration tests for Findings, SBOM, Remediation, and Reports endpoints.
"""
from app.models import (
    Assessment,
    AssessmentStatus,
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    SbomArtifact,
    SbomComponent,
)


def test_findings_filtering_and_sorting(client, auth_headers, test_project, test_repo, db):
    assessment = Assessment(
        project_id=test_project.id,
        repository_id=test_repo.id,
        created_by_id=test_project.owner_id,
        status=AssessmentStatus.COMPLETED,
    )
    db.add(assessment)
    db.flush()

    f1 = Finding(
        assessment_id=assessment.id,
        title="SQL Injection Vulnerability",
        category=FindingCategory.SAST,
        severity=FindingSeverity.CRITICAL,
        status=FindingStatus.OPEN,
        source_tool="semgrep",
        risk_score=9.5,
    )
    f2 = Finding(
        assessment_id=assessment.id,
        title="Missing CSP Header",
        category=FindingCategory.DAST,
        severity=FindingSeverity.MEDIUM,
        status=FindingStatus.OPEN,
        source_tool="dast",
        risk_score=5.0,
    )
    db.add_all([f1, f2])
    db.commit()

    # Filter by severity=CRITICAL
    resp = client.get(
        f"/api/v1/assessments/{assessment.id}/findings?severity=CRITICAL",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["title"] == "SQL Injection Vulnerability"

    # Filter by category=DAST
    resp_dast = client.get(
        f"/api/v1/assessments/{assessment.id}/findings?category=DAST",
        headers=auth_headers,
    )
    assert resp_dast.status_code == 200
    assert resp_dast.json()["total"] == 1
    assert resp_dast.json()["items"][0]["title"] == "Missing CSP Header"


def test_finding_disposition_update(client, auth_headers, test_project, test_repo, db):
    assessment = Assessment(
        project_id=test_project.id,
        repository_id=test_repo.id,
        created_by_id=test_project.owner_id,
        status=AssessmentStatus.COMPLETED,
    )
    db.add(assessment)
    db.flush()

    finding = Finding(
        assessment_id=assessment.id,
        title="False Positive Test Pattern",
        category=FindingCategory.SAST,
        severity=FindingSeverity.LOW,
        status=FindingStatus.OPEN,
        source_tool="semgrep",
    )
    db.add(finding)
    db.commit()

    # Update disposition
    payload = {
        "status": "FALSE_POSITIVE",
        "suppression_reason": "Verified benign test utility file.",
    }
    resp = client.put(f"/api/v1/findings/{finding.id}", json=payload, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "FALSE_POSITIVE"


def test_dependency_graph_endpoint(client, auth_headers, test_project, test_repo, db):
    assessment = Assessment(
        project_id=test_project.id,
        repository_id=test_repo.id,
        created_by_id=test_project.owner_id,
        status=AssessmentStatus.COMPLETED,
    )
    db.add(assessment)
    db.flush()

    sbom = SbomArtifact(
        assessment_id=assessment.id,
        format="cyclonedx-json",
        tool_name="syft",
    )
    db.add(sbom)
    db.flush()

    comp = SbomComponent(
        sbom_id=sbom.id,
        assessment_id=assessment.id,
        name="requests",
        version="2.6.0",
        purl="pkg:pypi/requests@2.6.0",
        is_direct=True,
    )
    db.add(comp)
    db.commit()

    resp = client.get(f"/api/v1/assessments/{assessment.id}/dependencies/graph", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data
    node_labels = [n["label"] for n in data["nodes"]]
    assert "requests" in node_labels


def test_report_generation_json(client, auth_headers, test_project, test_repo, db):
    assessment = Assessment(
        project_id=test_project.id,
        repository_id=test_repo.id,
        created_by_id=test_project.owner_id,
        status=AssessmentStatus.COMPLETED,
    )
    db.add(assessment)
    db.commit()

    resp = client.post(
        f"/api/v1/assessments/{assessment.id}/reports",
        json={"format": "json"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["format"] == "json"
    assert "id" in data


def test_report_generation_sarif(client, auth_headers, test_project, test_repo, db):
    assessment = Assessment(
        project_id=test_project.id,
        repository_id=test_repo.id,
        created_by_id=test_project.owner_id,
        status=AssessmentStatus.COMPLETED,
    )
    db.add(assessment)
    db.commit()

    resp = client.post(
        f"/api/v1/assessments/{assessment.id}/reports",
        json={"format": "sarif"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["format"] == "sarif"
