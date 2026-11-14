"""Validation for user-supplied Git clone URLs."""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import unquote, urlsplit


ALLOWED_GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}


def validate_clone_url(value: str | None, *, allow_local: bool = False) -> str | None:
    """Allow public HTTPS repository URLs from supported providers only.

    Local paths are retained for isolated development fixtures and are rejected
    in production. This prevents a remote user from making the worker copy
    arbitrary files from its host or targeting private network services.
    """
    if value is None:
        return None
    candidate = value.strip()
    if not candidate:
        return None

    if allow_local and Path(candidate).is_dir():
        return candidate

    parsed = urlsplit(candidate)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme.lower() != "https" or host not in ALLOWED_GIT_HOSTS:
        raise ValueError("Repository URL must use HTTPS on GitHub, GitLab, Bitbucket, or Codeberg.")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("Repository URL must not contain credentials or a custom port.")
    if parsed.query or parsed.fragment:
        raise ValueError("Repository URL must not contain a query string or fragment.")

    path_parts = [unquote(part) for part in parsed.path.split("/") if part]
    if len(path_parts) < 2 or any(part in {".", ".."} or "/" in part or "\\" in part for part in path_parts):
        raise ValueError("Repository URL must identify a repository path.")
    if host != "gitlab.com" and len(path_parts) != 2:
        raise ValueError("Repository URL must identify an owner and repository.")
    if path_parts[-1].endswith(".git"):
        path_parts[-1] = path_parts[-1][:-4]
    if any(not part or part.startswith("-") for part in path_parts):
        raise ValueError("Repository URL contains an invalid path component.")
    return candidate


def local_paths_allowed() -> bool:
    """Local fixture paths are permitted only outside production."""
    return os.getenv("APP_ENV", "development").strip().lower() not in {"prod", "production"}
