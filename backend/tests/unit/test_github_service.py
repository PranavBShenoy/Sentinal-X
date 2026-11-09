"""
Unit tests for GitHubService.

Verifies:
- OAuth authorization URL construction
- OAuth code exchange and error handling
- Repository listing with pagination traversal
- Repository metadata and commit SHA retrieval
- PR creation targeting repository default branch
- Rate limit header inspection and GitHubRateLimitError raising
- GitHub App token generation credential guard
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from app.services.github_service import GitHubRateLimitError, GitHubService


@pytest.fixture
def github_service():
    return GitHubService()


def test_get_oauth_url(github_service):
    with patch("app.services.github_service.settings") as mock_settings:
        mock_settings.GITHUB_CLIENT_ID = "gh-client-123"
        mock_settings.GITHUB_CALLBACK_URL = "http://localhost:8000/auth/github/callback"

        url = github_service.get_oauth_url(state="random-csrf-token-abc")
        assert "login/oauth/authorize" in url
        assert "client_id=gh-client-123" in url
        assert "state=random-csrf-token-abc" in url
        assert "repo%2Cread%3Auser" in url or "repo,read:user" in url


def test_exchange_code_success(github_service):
    async def _test():
        mock_token_resp = MagicMock(spec=httpx.Response)
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {
            "access_token": "gho_testtoken123456",
            "scope": "repo,read:user",
            "token_type": "bearer",
        }

        mock_user_resp = MagicMock(spec=httpx.Response)
        mock_user_resp.status_code = 200
        mock_user_resp.json.return_value = {
            "id": 12345,
            "login": "octocat",
            "email": "octocat@github.com",
        }
        mock_user_resp.headers = {"X-RateLimit-Remaining": "4999"}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post, \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_post.return_value = mock_token_resp
            mock_get.return_value = mock_user_resp

            result = await github_service.exchange_code("temp_code_123")
            assert result["access_token"] == "gho_testtoken123456"
            assert result["github_user"]["login"] == "octocat"
            assert result["token_type"] == "bearer"

    asyncio.run(_test())


def test_exchange_code_missing_token_raises(github_service):
    async def _test():
        mock_token_resp = MagicMock(spec=httpx.Response)
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {"error": "bad_verification_code"}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_token_resp
            with pytest.raises(ValueError, match="did not return an access token"):
                await github_service.exchange_code("invalid_code")

    asyncio.run(_test())


def test_list_repos_pagination(github_service):
    async def _test():
        # Page 1 response
        page1_resp = MagicMock(spec=httpx.Response)
        page1_resp.status_code = 200
        page1_resp.json.return_value = [{"id": 1, "name": "repo-one"}, {"id": 2, "name": "repo-two"}]
        page1_resp.headers = {"X-RateLimit-Remaining": "4990"}
        page1_resp.links = {"next": {"url": "https://api.github.com/user/repos?page=2"}}

        # Page 2 response (last page)
        page2_resp = MagicMock(spec=httpx.Response)
        page2_resp.status_code = 200
        page2_resp.json.return_value = [{"id": 3, "name": "repo-three"}]
        page2_resp.headers = {"X-RateLimit-Remaining": "4989"}
        page2_resp.links = {}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = [page1_resp, page2_resp]

            repos = await github_service.list_repos("mock-access-token")
            assert len(repos) == 3
            assert [r["name"] for r in repos] == ["repo-one", "repo-two", "repo-three"]
            assert mock_get.call_count == 2

    asyncio.run(_test())


def test_get_latest_commit(github_service):
    async def _test():
        commit_resp = MagicMock(spec=httpx.Response)
        commit_resp.status_code = 200
        commit_resp.json.return_value = {"sha": "abc1234567890abcdef1234567890abcdef12345"}
        commit_resp.headers = {"X-RateLimit-Remaining": "4980"}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = commit_resp

            sha = await github_service.get_latest_commit("octocat/Hello-World", "main", "mock-token")
            assert sha == "abc1234567890abcdef1234567890abcdef12345"

    asyncio.run(_test())


def test_create_pr_success(github_service):
    async def _test():
        repo_resp = MagicMock(spec=httpx.Response)
        repo_resp.status_code = 200
        repo_resp.json.return_value = {"default_branch": "main"}
        repo_resp.headers = {"X-RateLimit-Remaining": "4970"}

        pr_resp = MagicMock(spec=httpx.Response)
        pr_resp.status_code = 201
        pr_resp.json.return_value = {"html_url": "https://github.com/octocat/Hello-World/pull/42"}
        pr_resp.headers = {"X-RateLimit-Remaining": "4969"}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get, \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_get.return_value = repo_resp
            mock_post.return_value = pr_resp

            pr_url = await github_service.create_pr(
                full_name="octocat/Hello-World",
                branch="sentinelx-fix/vuln-1",
                title="Fix SQLi vulnerability",
                body="Automated remediation proposal from SENTINEL-X",
                access_token="mock-token",
            )
            assert pr_url == "https://github.com/octocat/Hello-World/pull/42"

    asyncio.run(_test())


def test_rate_limit_detection(github_service):
    # OK response
    resp_ok = MagicMock(spec=httpx.Response)
    resp_ok.headers = {"X-RateLimit-Remaining": "10"}
    github_service._check_rate_limit(resp_ok)  # Should not raise

    # Exhausted response
    resp_exhausted = MagicMock(spec=httpx.Response)
    resp_exhausted.headers = {
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": "1731234567",
    }
    with pytest.raises(GitHubRateLimitError) as exc_info:
        github_service._check_rate_limit(resp_exhausted)
    assert exc_info.value.reset_at == 1731234567


def test_get_installation_token_unconfigured(github_service):
    with patch("app.services.github_service.settings") as mock_settings:
        mock_settings.GITHUB_APP_ID = None
        mock_settings.GITHUB_APP_PRIVATE_KEY_PATH = None

        with pytest.raises(RuntimeError, match="credentials not configured"):
            github_service._get_installation_token("install-123")
