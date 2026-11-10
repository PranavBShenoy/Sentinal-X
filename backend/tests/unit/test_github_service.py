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
import hashlib
import hmac
import time
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
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
        repo_resp.json.return_value = {
            "default_branch": "main",
            "permissions": {"push": True, "admin": True},
        }
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


def test_oauth_state_cryptographic_verification(github_service):
    # 1. Valid state generated and verified
    state = github_service.generate_oauth_state()
    assert github_service.verify_oauth_state(state) is True

    # 2. Tampered nonce or timestamp fails
    parts = state.split(":")
    tampered = f"{parts[0]}:tampered_nonce:{parts[2]}"
    assert github_service.verify_oauth_state(tampered) is False

    # 3. Malformed state string fails closed
    assert github_service.verify_oauth_state("") is False
    assert github_service.verify_oauth_state("invalid-state") is False

    # 4. Expired state fails
    old_ts = int(time.time()) - 1000
    expired_raw = f"{old_ts}:{parts[1]}"
    from app.core.config import get_settings
    settings = get_settings()
    expired_sig = hmac.new(settings.JWT_SECRET.encode(), expired_raw.encode(), hashlib.sha256).hexdigest()
    expired_state = f"{expired_raw}:{expired_sig}"
    assert github_service.verify_oauth_state(expired_state, max_age_seconds=600) is False


def test_webhook_signature_verification(github_service):
    payload = b'{"action": "opened", "issue": {"number": 1}}'
    secret = "test-webhook-secret-xyz"

    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    valid_header = f"sha256={digest}"

    # Valid signature
    assert github_service.verify_webhook_signature(payload, valid_header, secret=secret) is True

    # Invalid / forged signature fails
    assert github_service.verify_webhook_signature(payload, "sha256=wrongdigest123456", secret=secret) is False

    # Missing signature or secret fails closed
    assert github_service.verify_webhook_signature(payload, None, secret=secret) is False
    assert github_service.verify_webhook_signature(payload, valid_header, secret="") is False


def test_check_repo_permission(github_service):
    async def _test():
        repo_data = {
            "name": "Hello-World",
            "permissions": {"admin": True, "push": True, "pull": True},
        }

        with patch.object(github_service, "get_repo", return_value=repo_data):
            can_push = await github_service.check_repo_permission("octocat/Hello-World", "token", "push")
            assert can_push is True

            can_maintain = await github_service.check_repo_permission("octocat/Hello-World", "token", "maintain")
            assert can_maintain is False

    asyncio.run(_test())


def test_oauth_state_one_time_consumption_replay_defense(github_service):
    """Verify state can only be consumed once, preventing replay attacks."""
    state = github_service.generate_oauth_state()

    # 1. First consumption succeeds
    first_res = github_service.consume_oauth_state(state)
    assert first_res is True

    # 2. Immediate replay attempt fails closed
    replay_res = github_service.consume_oauth_state(state)
    assert replay_res is False

    # 3. Invalid format fails closed
    assert github_service.consume_oauth_state("malformed") is False


def test_oauth_concurrent_login_attempts(github_service):
    """Verify concurrent login attempts generate distinct nonces that do not collide or invalidate each other."""
    state_a = github_service.generate_oauth_state()
    state_b = github_service.generate_oauth_state()

    assert state_a != state_b

    # Both states are cryptographically valid
    assert github_service.verify_oauth_state(state_a) is True
    assert github_service.verify_oauth_state(state_b) is True

    # Consuming state_a does not affect state_b
    assert github_service.consume_oauth_state(state_a) is True
    assert github_service.consume_oauth_state(state_b) is True

    # But neither can be replayed
    assert github_service.consume_oauth_state(state_a) is False
    assert github_service.consume_oauth_state(state_b) is False


def test_create_pr_unauthorized_permission_rejection(github_service):
    """Verify create_pr enforces server-side check and rejects users lacking write/push permissions."""
    async def _test():
        # Read-only permission metadata from GitHub API
        read_only_repo_data = {
            "name": "Hello-World",
            "default_branch": "main",
            "permissions": {"admin": False, "push": False, "pull": True},
        }

        with patch.object(github_service, "get_repo", return_value=read_only_repo_data), \
             patch("httpx.AsyncClient.post") as mock_post:

            with pytest.raises(PermissionError, match="lacks write/push permissions"):
                await github_service.create_pr(
                    full_name="octocat/Hello-World",
                    branch="fix-branch",
                    title="Fix vulnerability",
                    body="Patch",
                    access_token="read-only-token",
                )

            # Ensure no HTTP POST was sent to GitHub API pulls endpoint
            mock_post.assert_not_called()

    asyncio.run(_test())
