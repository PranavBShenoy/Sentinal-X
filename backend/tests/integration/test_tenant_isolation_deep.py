"""
Deep Tenant Isolation and Cross-User Access (IDOR / BOLA) Integration Tests.

Validates that multi-tenant boundaries are strictly enforced across all API endpoints:
- Projects (CRUD)
- Repositories
- Assessments (create, view, start, cancel)
- Security Findings (list, view, disposition update)
- SBOM & Dependency Graph
- Reports (generate, list, download)
- Remediation Proposals (list, view, approve, verify)

In every scenario, User 2 (attacker/unauthorized tenant) attempting to access, mutate,
or enumerate User 1's resources MUST receive HTTP 403 Forbidden or HTTP 404 Not Found,
and must never receive unauthorized data or leakage.
"""
from __future__ import annotations

import pytest
from app.models import (
    Assessment,
    AssessmentStatus,
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    Project,
    RemediationProposal,
    RemediationStatus,
    Report,
    Repository,
    SbomArtifact,
    SbomComponent,
)


@pytest.fixture
def user1_full_hierarchy(db, test_user, test_project, test_repo):
    """Sets up a complete resource hierarchy owned by User 1."""
    # Assessment
    assessment = Assessment(
        project_id=test_project.id,
        repository_id=test_repo.id,
        created_by_id=test_user.id,
        branch="main",
        status=AssessmentStatus.COMPLETED,
    )
    db.add(assessment)
    db.flush()

    # Finding
    finding = Finding(
        assessment_id=assessment.id,
        title="Cross-Tenant Target Finding",
        category=FindingCategory.SAST,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        source_tool="semgrep",
        risk_score=8.5,
    )
    db.add(finding)
    db.flush()

    # SBOM Artifact & Component
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
        name="isolated-lib",
        version="1.0.0",
        purl="pkg:pypi/isolated-lib@1.0.0",
        is_direct=True,
    )
    db.add(comp)

    # Report
    report = Report(
        assessment_id=assessment.id,
        generated_by_id=test_user.id,
        format="json",
        file_path="/tmp/sentinelx_dummy_report.json",
    )
    db.add(report)
    db.flush()

    # Remediation Proposal
    proposal = RemediationProposal(
        finding_id=finding.id,
        assessment_id=assessment.id,
        created_by_id=test_user.id,
        status=RemediationStatus.PROPOSED,
        summary="Fix Secret Leak",
        patch_diff="--- a/secret.py\n+++ b/secret.py\n@@ -1 +1 @@\n-secret=123\n+secret=os.getenv('SECRET')",
    )
    db.add(proposal)
    db.commit()

    return {
        "project": test_project,
        "repo": test_repo,
        "assessment": assessment,
        "finding": finding,
        "sbom": sbom,
        "component": comp,
        "report": report,
        "proposal": proposal,
    }


def test_tenant_isolation_projects_crud(client, auth_headers_2, user1_full_hierarchy):
    """User 2 must not be able to view, update, or delete User 1's project."""
    project_id = user1_full_hierarchy["project"].id

    # Read
    r_get = client.get(f"/api/v1/projects/{project_id}", headers=auth_headers_2)
    assert r_get.status_code in (403, 404)

    # Update
    r_put = client.put(
        f"/api/v1/projects/{project_id}",
        json={"name": "Hacked Project Name"},
        headers=auth_headers_2,
    )
    assert r_put.status_code in (403, 404)

    # Delete
    r_del = client.delete(f"/api/v1/projects/{project_id}", headers=auth_headers_2)
    assert r_del.status_code in (403, 404)


def test_tenant_isolation_repositories(client, auth_headers_2, user1_full_hierarchy):
    """User 2 must not be able to list or attach repositories to User 1's project."""
    project_id = user1_full_hierarchy["project"].id

    # List repos
    r_list = client.get(f"/api/v1/projects/{project_id}/repositories", headers=auth_headers_2)
    assert r_list.status_code in (403, 404)

    # Add repo
    r_add = client.post(
        f"/api/v1/projects/{project_id}/repositories",
        json={"full_name": "attacker/injected-repo", "clone_url": "https://github.com/attacker/injected-repo.git"},
        headers=auth_headers_2,
    )
    assert r_add.status_code in (403, 404)


def test_tenant_isolation_assessments(client, auth_headers_2, user1_full_hierarchy):
    """User 2 must not be able to create, read, trigger, or cancel User 1's assessments."""
    project_id = user1_full_hierarchy["project"].id
    repo_id = user1_full_hierarchy["repo"].id
    assessment_id = user1_full_hierarchy["assessment"].id

    # Create assessment on User 1's project
    r_create = client.post(
        f"/api/v1/projects/{project_id}/assessments",
        json={"repository_id": str(repo_id), "branch": "main"},
        headers=auth_headers_2,
    )
    assert r_create.status_code in (403, 404)

    # Read User 1's assessment
    r_read = client.get(f"/api/v1/assessments/{assessment_id}", headers=auth_headers_2)
    assert r_read.status_code in (403, 404)

    # Trigger start on User 1's assessment
    r_start = client.post(f"/api/v1/assessments/{assessment_id}/start", headers=auth_headers_2)
    assert r_start.status_code in (403, 404)

    # Cancel User 1's assessment
    r_cancel = client.delete(f"/api/v1/assessments/{assessment_id}/cancel", headers=auth_headers_2)
    assert r_cancel.status_code in (403, 404)


def test_tenant_isolation_findings(client, auth_headers_2, user1_full_hierarchy):
    """User 2 must not see or modify User 1's findings, nor see them in global listing."""
    finding_id = user1_full_hierarchy["finding"].id

    # Read single finding
    r_read = client.get(f"/api/v1/findings/{finding_id}", headers=auth_headers_2)
    assert r_read.status_code in (403, 404)

    # Mutate finding disposition
    r_put = client.put(
        f"/api/v1/findings/{finding_id}",
        json={"status": "FALSE_POSITIVE", "suppression_reason": "Attacker suppression attempt"},
        headers=auth_headers_2,
    )
    assert r_put.status_code in (403, 404)

    # List findings for User 2 — must NOT include User 1's finding
    r_list = client.get("/api/v1/findings", headers=auth_headers_2)
    assert r_list.status_code == 200
    user2_findings = r_list.json()
    assert user2_findings["total"] == 0
    assert len(user2_findings["items"]) == 0


def test_tenant_isolation_sbom_and_dependency_graph(client, auth_headers_2, user1_full_hierarchy):
    """User 2 must not be able to access User 1's SBOM or dependency graph."""
    assessment_id = user1_full_hierarchy["assessment"].id
    sbom_id = user1_full_hierarchy["sbom"].id

    # List SBOMs
    r_sboms = client.get(f"/api/v1/assessments/{assessment_id}/sbom", headers=auth_headers_2)
    assert r_sboms.status_code in (403, 404)

    # List SBOM components
    r_comps = client.get(
        f"/api/v1/assessments/{assessment_id}/sbom/{sbom_id}/components",
        headers=auth_headers_2,
    )
    assert r_comps.status_code in (403, 404)

    # Dependency graph
    r_graph = client.get(
        f"/api/v1/assessments/{assessment_id}/dependencies/graph",
        headers=auth_headers_2,
    )
    assert r_graph.status_code in (403, 404)


def test_tenant_isolation_reports(client, auth_headers_2, user1_full_hierarchy):
    """User 2 must not be able to generate, list, or download User 1's reports."""
    assessment_id = user1_full_hierarchy["assessment"].id
    report_id = user1_full_hierarchy["report"].id

    # List reports
    r_list = client.get(f"/api/v1/assessments/{assessment_id}/reports", headers=auth_headers_2)
    assert r_list.status_code in (403, 404)

    # Generate report
    r_gen = client.post(
        f"/api/v1/assessments/{assessment_id}/reports",
        json={"format": "json"},
        headers=auth_headers_2,
    )
    assert r_gen.status_code in (403, 404)

    # Download report
    r_dl = client.get(f"/api/v1/reports/{report_id}/download", headers=auth_headers_2)
    assert r_dl.status_code in (403, 404)


def test_tenant_isolation_remediation_proposals(client, auth_headers_2, user1_full_hierarchy):
    """User 2 must not view, approve, or verify User 1's remediation proposals."""
    assessment_id = user1_full_hierarchy["assessment"].id
    proposal_id = user1_full_hierarchy["proposal"].id

    # List proposals for assessment
    r_list = client.get(
        f"/api/v1/assessments/{assessment_id}/remediations",
        headers=auth_headers_2,
    )
    assert r_list.status_code in (403, 404)

    # Get single proposal
    r_get = client.get(f"/api/v1/remediations/{proposal_id}", headers=auth_headers_2)
    assert r_get.status_code in (403, 404)

    # Approve proposal
    r_app = client.post(
        f"/api/v1/remediations/{proposal_id}/approve",
        json={"approved": True},
        headers=auth_headers_2,
    )
    assert r_app.status_code in (403, 404)

    # Verify proposal
    r_ver = client.post(
        f"/api/v1/remediations/{proposal_id}/verify",
        headers=auth_headers_2,
    )
    assert r_ver.status_code in (403, 404)
