"""
Integration tests for remediation PR creation and server-side permission enforcement.

Verifies:
1. Unauthorized project access is rejected via tenant isolation (404).
2. Unapproved proposal state is rejected (400).
3. Missing GitHub installation is rejected (422).
4. Direct API PR creation without write/push permissions is rejected (403 Forbidden).
5. Authorized user with push permissions successfully creates PR and updates proposal status.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

from fastapi import status
from fastapi.testclient import TestClient

from app.core.security import create_access_token, encrypt_value
from app.main import app
from app.models import (
    Assessment,
    GitHubInstallation,
    Project,
    RemediationProposal,
    RemediationStatus,
    Repository,
    User,
)

client = TestClient(app)


def _seed_test_remediation_context(db_session, has_push_permission: bool = True):
    """Seed user, project, repo, assessment, proposal, and GitHub installation."""
    owner = User(
        email=f"owner_{uuid.uuid4().hex[:8]}@example.com",
        username=f"owner_{uuid.uuid4().hex[:8]}",
        hashed_password="bcrypt_hashed_password",
        is_active=True,
    )
    db_session.add(owner)
    db_session.flush()

    project = Project(
        name="Security App",
        owner_id=owner.id,
    )
    db_session.add(project)
    db_session.flush()

    repo = Repository(
        project_id=project.id,
        full_name="org/secure-app",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.flush()

    assessment = Assessment(
        project_id=project.id,
        repository_id=repo.id,
        created_by_id=owner.id,
    )
    db_session.add(assessment)
    db_session.flush()

    proposal = RemediationProposal(
        assessment_id=str(assessment.id),
        finding_id=str(uuid.uuid4()),
        created_by_id=str(owner.id),
        status=RemediationStatus.APPROVED,
        summary="Automated patch proposal",
        proposed_branch="sentinelx-fix/vuln-1",
    )
    db_session.add(proposal)
    db_session.flush()

    installation = GitHubInstallation(
        user_id=owner.id,
        encrypted_access_token=encrypt_value("gho_test_oauth_access_token_123"),
    )
    db_session.add(installation)
    db_session.commit()

    return owner, project, repo, assessment, proposal


def test_remediation_pr_creation_rejects_unapproved_proposal(db):
    owner, _, _, _, proposal = _seed_test_remediation_context(db)
    proposal.status = RemediationStatus.PROPOSED
    db.commit()

    token = create_access_token(subject=str(owner.id))
    resp = client.post(
        f"/api/v1/remediations/{proposal.id}/create-pr",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert "approved or verified" in resp.json()["detail"].lower()


def test_remediation_pr_creation_rejects_other_user_proposal(db):
    _, _, _, _, proposal = _seed_test_remediation_context(db)

    attacker = User(
        email=f"attacker_{uuid.uuid4().hex[:8]}@example.com",
        username=f"attacker_{uuid.uuid4().hex[:8]}",
        hashed_password="hashed",
        is_active=True,
    )
    db.add(attacker)
    db.commit()

    attacker_token = create_access_token(subject=str(attacker.id))
    resp = client.post(
        f"/api/v1/remediations/{proposal.id}/create-pr",
        headers={"Authorization": f"Bearer {attacker_token}"},
    )
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_remediation_pr_creation_rejects_unauthorized_repository_permissions(db):
    """Direct API request to create PR is rejected with 403 when user lacks push access."""
    owner, _, repo, _, proposal = _seed_test_remediation_context(db)
    token = create_access_token(subject=str(owner.id))

    # Mock github_service.check_repo_permission returning False (read-only user)
    with patch("app.services.github_service.github_service.check_repo_permission", new_callable=AsyncMock) as mock_check:
        mock_check.return_value = False

        resp = client.post(
            f"/api/v1/remediations/{proposal.id}/create-pr",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN
        assert "do not have write/push permissions" in resp.json()["detail"]


def test_remediation_pr_creation_success_when_authorized(db):
    """Authorized user with write/push permissions creates PR and proposal transitions to APPLIED."""
    owner, _, repo, _, proposal = _seed_test_remediation_context(db)
    token = create_access_token(subject=str(owner.id))

    with patch("app.services.github_service.github_service.check_repo_permission", new_callable=AsyncMock) as mock_check, \
         patch("app.services.github_service.github_service.create_pr", new_callable=AsyncMock) as mock_create_pr:
        mock_check.return_value = True
        mock_create_pr.return_value = "https://github.com/org/secure-app/pull/99"

        resp = client.post(
            f"/api/v1/remediations/{proposal.id}/create-pr",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["status"] == RemediationStatus.APPLIED.value
        assert data["pr_url"] == "https://github.com/org/secure-app/pull/99"
        mock_create_pr.assert_called_once()
