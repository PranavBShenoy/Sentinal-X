"""
Integration tests for assessment management and SSRF protection.
"""
def test_create_assessment_success(client, auth_headers, test_project, test_repo):
    payload = {
        "repository_id": str(test_repo.id),
        "branch": "main",
        "config": {
            "scan_depth": "standard",
            "enable_active_dast": False,
        },
    }
    resp = client.post(
        f"/api/v1/projects/{test_project.id}/assessments",
        json=payload,
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "CREATED"
    assert data["branch"] == "main"
    assert "id" in data


def test_ssrf_protection_loopback_rejected(client, auth_headers, test_project, test_repo):
    """
    CRITICAL SECURITY TEST:
    Verify that staging URLs pointing to localhost / 127.0.0.1 are rejected.
    """
    payload = {
        "repository_id": str(test_repo.id),
        "config": {
            "target_url": "http://127.0.0.1:8080/api",
        },
    }
    resp = client.post(
        f"/api/v1/projects/{test_project.id}/assessments",
        json=payload,
        headers=auth_headers,
    )
    assert resp.status_code == 400
    assert "SSRF Blocked" in resp.json()["detail"]


def test_ssrf_protection_metadata_ip_rejected(client, auth_headers, test_project, test_repo):
    """
    CRITICAL SECURITY TEST:
    Verify that cloud metadata address (169.254.169.254) is blocked.
    """
    payload = {
        "repository_id": str(test_repo.id),
        "config": {
            "target_url": "http://169.254.169.254/latest/meta-data/",
        },
    }
    resp = client.post(
        f"/api/v1/projects/{test_project.id}/assessments",
        json=payload,
        headers=auth_headers,
    )
    assert resp.status_code == 400
    assert "SSRF Blocked" in resp.json()["detail"]


def test_assessment_progress_endpoint(client, auth_headers, test_project, test_repo, db):
    from app.models import Assessment, AssessmentStatus

    assessment = Assessment(
        project_id=test_project.id,
        repository_id=test_repo.id,
        created_by_id=test_project.owner_id,
        status=AssessmentStatus.CREATED,
    )
    db.add(assessment)
    db.commit()

    resp = client.get(f"/api/v1/assessments/{assessment.id}/progress", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "CREATED"
    assert "scan_jobs" in data
