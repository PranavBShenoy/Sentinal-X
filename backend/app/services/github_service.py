"""
GitHub integration service for SENTINEL-X.

Provides OAuth flow, repository listing, commit inspection, and PR creation.
Respects GitHub API rate limits via X-RateLimit-* headers.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

GITHUB_API_BASE = "https://api.github.com"
GITHUB_OAUTH_BASE = "https://github.com"


class GitHubRateLimitError(Exception):
    """Raised when GitHub API rate limit is exhausted."""
    def __init__(self, reset_at: Optional[int] = None):
        self.reset_at = reset_at
        super().__init__("GitHub API rate limit exceeded.")


class GitHubService:
    """High-level GitHub API client."""

    # --------------------------------------------------------------------- #
    # OAuth helpers
    # --------------------------------------------------------------------- #

    def generate_oauth_state(self) -> str:
        """
        Generate a cryptographically signed OAuth state parameter.
        Format: {timestamp}:{nonce}:{hmac_signature}
        """
        now = int(time.time())
        nonce = secrets.token_hex(16)
        raw = f"{now}:{nonce}"
        sig = hmac.new(
            settings.JWT_SECRET.encode("utf-8"),
            raw.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"{raw}:{sig}"

    def verify_oauth_state(self, state: str, max_age_seconds: int = 600) -> bool:
        """
        Verify the signature and timestamp of an OAuth state parameter.
        Fails closed on missing, malformed, expired, or forged states.
        """
        if not state or ":" not in state:
            return False
        parts = state.split(":")
        if len(parts) != 3:
            return False
        ts_str, nonce, received_sig = parts
        try:
            ts = int(ts_str)
        except ValueError:
            return False

        # Expiry check (default 10 minutes)
        if time.time() - ts > max_age_seconds or ts > time.time() + 60:
            return False

        raw = f"{ts}:{nonce}"
        expected_sig = hmac.new(
            settings.JWT_SECRET.encode("utf-8"),
            raw.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(received_sig, expected_sig)

    # In-memory thread-safe state consumption tracker for replay prevention
    _consumed_states: dict[str, float] = {}
    _consumed_lock = threading.Lock()

    def consume_oauth_state(self, state: str) -> bool:
        """
        Mark an OAuth state as consumed to prevent replay attacks (one-time consumption).
        Returns True if state was successfully consumed (first time).
        Returns False if state was already consumed (replay attack detected).
        """
        if not state or ":" not in state:
            return False
        parts = state.split(":")
        if len(parts) != 3:
            return False
        nonce = parts[1]

        # 1. Distributed replay prevention via Redis (shared across all workers).
        #    Required in production; development may degrade to a per-process
        #    in-memory fallback only when Redis is unavailable.
        try:
            import redis
            r = redis.from_url(settings.REDIS_URL, decode_responses=True)
            # Set key with NX (only if Not eXists) and 600s TTL.
            res = r.set(f"sentinelx:oauth_consumed:{nonce}", "1", ex=600, nx=True)
            if not res:
                return False  # Already consumed in Redis!
            return True
        except Exception as exc:
            logger.warning("Redis unavailable for OAuth state consumption: %s", str(exc))
            if settings.APP_ENV == "production":
                # Fail closed in production: never allow an insecure,
                # per-process in-memory replay-prevention fallback across workers.
                return False
            # 2. Development-only: thread-safe in-memory cache (NOT shared
            #    across workers — acceptable only for local single-worker dev).
            return self._consume_local_nonce(nonce)

    def _consume_local_nonce(self, nonce: str) -> bool:
        now = time.time()
        with self._consumed_lock:
            # Prune expired nonces (>600 seconds)
            expired = [k for k, exp in self._consumed_states.items() if exp < now]
            for k in expired:
                del self._consumed_states[k]

            if nonce in self._consumed_states:
                return False  # Replay detected!
            self._consumed_states[nonce] = now + 600
            return True

    def verify_webhook_signature(
        self,
        payload: bytes,
        signature_header: Optional[str],
        secret: Optional[str] = None,
    ) -> bool:
        """
        Verify GitHub webhook payload signature against X-Hub-Signature-256.
        Uses constant-time comparison to prevent timing attacks.
        """
        webhook_secret = secret or getattr(settings, "GITHUB_WEBHOOK_SECRET", None)
        if not webhook_secret or not signature_header:
            return False

        # GitHub format: sha256=<hex_digest>
        if not signature_header.startswith("sha256="):
            return False
        received_digest = signature_header[7:]

        expected_digest = hmac.new(
            webhook_secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(received_digest, expected_digest)

    async def check_repo_permission(
        self, full_name: str, access_token: str, required_permission: str = "push"
    ) -> bool:
        """Verify whether the user has the required permission on the repository."""
        try:
            repo_data = await self.get_repo(full_name, access_token)
            permissions = repo_data.get("permissions", {})
            return bool(permissions.get(required_permission, False))
        except Exception as e:
            logger.warning("Failed to check repo permission for %s: %s", full_name, e)
            return False

    def get_oauth_url(self, state: str) -> str:
        """Return the GitHub OAuth authorization URL."""
        client_id = settings.GITHUB_CLIENT_ID or ""
        scope = "repo,read:user,user:email"
        return (
            f"{GITHUB_OAUTH_BASE}/login/oauth/authorize"
            f"?client_id={client_id}"
            f"&redirect_uri={settings.GITHUB_CALLBACK_URL}"
            f"&scope={scope}"
            f"&state={state}"
        )

    async def exchange_code(self, code: str) -> Dict[str, Any]:
        """
        Exchange OAuth authorization code for an access token.

        Returns a dict with keys: access_token, scope, token_type, github_user.
        """
        async with httpx.AsyncClient(timeout=15) as client:
            token_resp = await client.post(
                f"{GITHUB_OAUTH_BASE}/login/oauth/access_token",
                json={
                    "client_id": settings.GITHUB_CLIENT_ID,
                    "client_secret": settings.GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": settings.GITHUB_CALLBACK_URL,
                },
                headers={"Accept": "application/json"},
            )
            token_resp.raise_for_status()
            token_data = token_resp.json()

        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError("GitHub did not return an access token.")

        user_info = await self._get_user(access_token)
        return {
            "access_token": access_token,
            "scope": token_data.get("scope", ""),
            "token_type": token_data.get("token_type", "bearer"),
            "github_user": user_info,
        }

    # --------------------------------------------------------------------- #
    # Repository operations
    # --------------------------------------------------------------------- #

    async def list_repos(self, access_token: str) -> List[Dict[str, Any]]:
        """List all repositories accessible to the authenticated user."""
        repos: List[Dict[str, Any]] = []
        url = f"{GITHUB_API_BASE}/user/repos"
        params = {"per_page": 100, "sort": "updated", "type": "all"}

        async with httpx.AsyncClient(timeout=30) as client:
            while url:
                resp = await self._get(client, url, access_token, params=params)
                repos.extend(resp.json())
                # Follow pagination links
                url = resp.links.get("next", {}).get("url")
                params = {}  # Next URL already contains params

        return repos

    async def get_repo(self, full_name: str, access_token: str) -> Dict[str, Any]:
        """Get metadata for a single repository by its full name."""
        url = f"{GITHUB_API_BASE}/repos/{full_name}"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await self._get(client, url, access_token)
        return resp.json()

    async def get_latest_commit(
        self, full_name: str, branch: str, access_token: str
    ) -> str:
        """Return the SHA of the latest commit on the given branch."""
        url = f"{GITHUB_API_BASE}/repos/{full_name}/commits/{branch}"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await self._get(client, url, access_token)
        return resp.json()["sha"]

    async def create_pr(
        self,
        full_name: str,
        branch: str,
        title: str,
        body: str,
        access_token: str,
    ) -> str:
        """Create a pull request and return its URL."""
        # 1. Fetch repo metadata and verify default branch
        repo_data = await self.get_repo(full_name, access_token)

        # 2. Server-side permission check: Verify write / push permission before attempting PR
        permissions = repo_data.get("permissions", {})
        if permissions and not (permissions.get("push") or permissions.get("admin")):
            raise PermissionError(
                f"Unauthorized: GitHub account lacks write/push permissions on repository '{full_name}'."
            )

        base_branch = repo_data.get("default_branch", "main")
        url = f"{GITHUB_API_BASE}/repos/{full_name}/pulls"

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                url,
                json={"title": title, "body": body, "head": branch, "base": base_branch},
                headers=self._auth_headers(access_token),
            )
            self._check_rate_limit(resp)
            resp.raise_for_status()

        return resp.json()["html_url"]

    # --------------------------------------------------------------------- #
    # GitHub App — installation token
    # --------------------------------------------------------------------- #

    def _get_installation_token(self, installation_id: str) -> str:
        """
        Generate a short-lived installation access token for a GitHub App.

        Requires GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY_PATH to be set.
        """
        import jwt as pyjwt

        app_id = settings.GITHUB_APP_ID
        key_path = settings.GITHUB_APP_PRIVATE_KEY_PATH
        if not app_id or not key_path:
            raise RuntimeError("GitHub App credentials not configured.")

        with open(key_path, "rb") as fh:
            private_key = fh.read()

        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 600, "iss": app_id}
        app_jwt = pyjwt.encode(payload, private_key, algorithm="RS256")

        import httpx as _httpx
        resp = _httpx.post(
            f"{GITHUB_API_BASE}/app/installations/{installation_id}/access_tokens",
            headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"},
        )
        resp.raise_for_status()
        return resp.json()["token"]

    # --------------------------------------------------------------------- #
    # Private helpers
    # --------------------------------------------------------------------- #

    async def _get_user(self, access_token: str) -> Dict[str, Any]:
        url = f"{GITHUB_API_BASE}/user"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await self._get(client, url, access_token)
        return resp.json()

    async def _get(
        self,
        client: httpx.AsyncClient,
        url: str,
        access_token: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        resp = await client.get(url, headers=self._auth_headers(access_token), params=params)
        self._check_rate_limit(resp)
        resp.raise_for_status()
        return resp

    @staticmethod
    def _auth_headers(access_token: str) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    @staticmethod
    def _check_rate_limit(resp: httpx.Response) -> None:
        remaining = resp.headers.get("X-RateLimit-Remaining")
        if remaining is not None and int(remaining) == 0:
            reset_at = resp.headers.get("X-RateLimit-Reset")
            raise GitHubRateLimitError(reset_at=int(reset_at) if reset_at else None)


# Module-level singleton.
github_service = GitHubService()
