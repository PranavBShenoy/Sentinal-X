"""Unit tests for private repository authentication, PAT encryption, and credential handling."""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.core.security import decrypt_value, encrypt_value
from app.models.models import Assessment, Repository
from app.schemas.schemas import RepositoryCreate, RepositoryResponse
from app.services.repository_service import RepositoryService


def test_repository_create_schema_auth_token():
    """Verify RepositoryCreate accepts and strips auth_token."""
    payload = RepositoryCreate(
        full_name="owner/private-repo",
        clone_url="https://github.com/owner/private-repo.git",
        auth_token="  ghp_my_secret_pat_token_12345  ",
        auth_token_type="pat",
    )
    assert payload.auth_token == "ghp_my_secret_pat_token_12345"
    assert payload.auth_token_type == "pat"


def test_repository_model_encryption_and_preview():
    """Verify repository model encrypts PAT and exposes only masked preview."""
    raw_token = "ghp_secure_personal_access_token_9999"
    encrypted = encrypt_value(raw_token)

    repo = Repository(
        project_id=uuid.uuid4(),
        full_name="org/secure-repo",
        clone_url="https://github.com/org/secure-repo.git",
        is_private=True,
        encrypted_auth_token=encrypted,
        auth_token_type="pat",
    )

    assert repo.has_auth_token is True
    assert repo.encrypted_auth_token != raw_token
    assert decrypt_value(repo.encrypted_auth_token) == raw_token
    # Masked preview must obscure the middle of the token
    preview = repo.auth_token_preview
    assert preview is not None
    assert preview.startswith("ghp_")
    assert preview.endswith("9999")
    assert "secure_personal_access" not in preview


from datetime import datetime, timezone

def test_repository_response_never_leaks_plaintext_token():
    """Verify RepositoryResponse serializes preview and flag without exposing plaintext."""
    raw_token = "glpat-gitlab_secret_token_123456"
    repo = Repository(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        full_name="gitlab-group/private-project",
        clone_url="https://gitlab.com/gitlab-group/private-project.git",
        is_private=True,
        encrypted_auth_token=encrypt_value(raw_token),
        auth_token_type="pat",
        created_at=datetime.now(timezone.utc),
    )

    resp = RepositoryResponse.model_validate(repo)
    data = resp.model_dump()
    assert data["has_auth_token"] is True
    assert data["auth_token_type"] == "pat"
    assert "glpat-" in data["auth_token_preview"]
    assert "auth_token" not in data or data.get("auth_token") is None
    assert raw_token not in str(data)


@patch("app.services.repository_service.run_command")
def test_clone_repo_with_direct_pat_github(mock_run, tmp_path):
    """Verify RepositoryService.fetch injects PAT into GitHub clone URL and runs git clone."""
    service = RepositoryService()
    assessment_id = uuid.uuid4()
    raw_pat = "ghp_test_token_abc_123"

    mock_run.return_value = MagicMock(succeeded=True, stdout="c0ffee\n", stderr="")

    repo = Repository(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        full_name="octocat/private-tool",
        clone_url="https://github.com/octocat/private-tool.git",
        default_branch="main",
        is_private=True,
        encrypted_auth_token=encrypt_value(raw_pat),
        auth_token_type="pat",
        created_at=datetime.now(timezone.utc),
    )

    assessment = Assessment(
        id=assessment_id,
        project_id=repo.project_id,
        repository_id=repo.id,
        created_by_id=uuid.uuid4(),
        branch="main",
    )
    assessment.repository = repo

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = assessment

    with patch("app.services.repository_service.db_session") as mock_session_ctx, \
         patch("app.services.repository_service.get_settings") as mock_settings:
        mock_session_ctx.return_value.__enter__.return_value = mock_db
        mock_settings.return_value.ASSESSMENT_WORKSPACE_BASE = str(tmp_path)

        res = service.fetch(str(assessment_id))
        assert res["commit_sha"] == "c0ffee"

        # Verify git clone was called with x-access-token
        first_call_args = mock_run.call_args_list[0].kwargs.get("args") or mock_run.call_args_list[0][0][0]
        clone_url_arg = first_call_args[6]
        assert f"x-access-token:{raw_pat}@github.com" in clone_url_arg


@patch("app.services.repository_service.run_command")
def test_clone_repo_with_gitlab_pat(mock_run, tmp_path):
    """Verify RepositoryService.fetch formats oauth2 credential for GitLab."""
    service = RepositoryService()
    assessment_id = uuid.uuid4()
    gitlab_pat = "glpat-gitlab_deploy_token_xyz"

    mock_run.return_value = MagicMock(succeeded=True, stdout="deadbeef\n", stderr="")

    repo = Repository(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        full_name="my-group/subgroup/private-repo",
        clone_url="https://gitlab.com/my-group/subgroup/private-repo.git",
        default_branch="main",
        is_private=True,
        encrypted_auth_token=encrypt_value(gitlab_pat),
        auth_token_type="pat",
        created_at=datetime.now(timezone.utc),
    )

    assessment = Assessment(
        id=assessment_id,
        project_id=repo.project_id,
        repository_id=repo.id,
        created_by_id=uuid.uuid4(),
        branch="main",
    )
    assessment.repository = repo

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = assessment

    with patch("app.services.repository_service.db_session") as mock_session_ctx, \
         patch("app.services.repository_service.get_settings") as mock_settings:
        mock_session_ctx.return_value.__enter__.return_value = mock_db
        mock_settings.return_value.ASSESSMENT_WORKSPACE_BASE = str(tmp_path)

        service.fetch(str(assessment_id))

        first_call_args = mock_run.call_args_list[0].kwargs.get("args") or mock_run.call_args_list[0][0][0]
        clone_url_arg = first_call_args[6]
        assert f"oauth2:{gitlab_pat}@gitlab.com" in clone_url_arg


@patch("app.services.repository_service.run_command")
def test_clone_repo_sanitizes_errors(mock_run, tmp_path):
    """Verify error messages sanitize and never leak credentials."""
    service = RepositoryService()
    assessment_id = uuid.uuid4()
    secret_pat = "ghp_super_secret_pat_9876543210"

    mock_run.return_value = MagicMock(
        succeeded=False,
        stdout="",
        stderr=f"fatal: Authentication failed for 'https://x-access-token:{secret_pat}@github.com/org/private.git'",
    )

    repo = Repository(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        full_name="org/private",
        clone_url="https://github.com/org/private.git",
        default_branch="main",
        is_private=True,
        encrypted_auth_token=encrypt_value(secret_pat),
        created_at=datetime.now(timezone.utc),
    )

    assessment = Assessment(
        id=assessment_id,
        project_id=repo.project_id,
        repository_id=repo.id,
        created_by_id=uuid.uuid4(),
        branch="main",
    )
    assessment.repository = repo

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = assessment

    with patch("app.services.repository_service.db_session") as mock_session_ctx, \
         patch("app.services.repository_service.get_settings") as mock_settings:
        mock_session_ctx.return_value.__enter__.return_value = mock_db
        mock_settings.return_value.ASSESSMENT_WORKSPACE_BASE = str(tmp_path)

        with pytest.raises(RuntimeError) as exc_info:
            service.fetch(str(assessment_id))

        error_message = str(exc_info.value)
        assert secret_pat not in error_message
        assert "[REDACTED]" in error_message
