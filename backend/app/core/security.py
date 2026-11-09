"""
JWT and password security utilities for SENTINEL-X.

Security principles:
- bcrypt for password hashing (adaptive, resistant to brute-force)
- JWT HS256 for short-lived access tokens (30 min default)
- Refresh tokens stored server-side as hashed values
- No secrets in logs or error messages
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import bcrypt
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.core.config import get_settings

settings = get_settings()


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    """Hash a plaintext password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JWT access tokens
# ---------------------------------------------------------------------------

def create_access_token(
    subject: str,
    extra_claims: Optional[dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": expire,
        "type": "access",
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and verify a JWT access token.

    Raises jwt.exceptions.InvalidTokenError subclasses on failure.
    Callers should handle ExpiredSignatureError and InvalidTokenError.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["sub", "exp", "iat"]},
    )


# ---------------------------------------------------------------------------
# Refresh tokens — opaque, stored as SHA-256 hash in DB
# ---------------------------------------------------------------------------

def generate_refresh_token() -> tuple[str, str]:
    """
    Generate an opaque refresh token.

    Returns (plain_token, hashed_token).
    Store only the hash. Send plain_token to client.
    """
    plain = secrets.token_urlsafe(64)
    hashed = hashlib.sha256(plain.encode()).hexdigest()
    return plain, hashed


def hash_refresh_token(plain: str) -> str:
    """Hash a refresh token for storage."""
    return hashlib.sha256(plain.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Field-level encryption for sensitive DB values (e.g. GitHub tokens)
# ---------------------------------------------------------------------------

def get_fernet():
    """Return a Fernet instance for field encryption."""
    from cryptography.fernet import Fernet, InvalidToken  # noqa: F401
    key = settings.ENCRYPTION_KEY
    if not key:
        raise RuntimeError(
            "ENCRYPTION_KEY is not set. Cannot encrypt sensitive configuration."
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_value(plain: str) -> str:
    """Encrypt a string value for secure DB storage."""
    f = get_fernet()
    return f.encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt_value(ciphertext: str) -> str:
    """Decrypt a stored ciphertext value."""
    f = get_fernet()
    return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
