"""Construction of the Control Plane capability-token signer."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from app.authz.component import AuthorizationComponent
from app.core.config import get_settings


@lru_cache(maxsize=1)
def get_authorization_component() -> AuthorizationComponent:
    """Load the configured signer; never generate an ephemeral production key."""
    settings = get_settings()
    private_path = settings.JOB_TOKEN_PRIVATE_KEY_PATH
    public_path = settings.JOB_TOKEN_PUBLIC_KEY_PATH
    if not private_path or not public_path:
        raise RuntimeError(
            "JOB_TOKEN_PRIVATE_KEY_PATH and JOB_TOKEN_PUBLIC_KEY_PATH are required "
            "to authorize Runtime Host jobs"
        )
    private_key = Path(private_path)
    public_key = Path(public_path)
    if not private_key.is_file() or not public_key.is_file():
        raise RuntimeError("Configured job-token signing key files are unavailable")
    return AuthorizationComponent(
        private_key_pem=private_key.read_bytes(),
        public_key_pem=public_key.read_bytes(),
    )
