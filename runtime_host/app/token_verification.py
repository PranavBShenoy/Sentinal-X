"""Ed25519 job-token verification for the Runtime Host.

This module is intentionally self-contained: the Runtime Host must not import
control-plane code (``app.runtime.*``). Sharing an import path would couple the
execution plane to control-plane packages and force the Runtime Host image to
ship the entire backend and its dependency tree.

Only verification lives here. The signing key and signing code remain in the
control-plane Authorization Component and never reach this host. A
cross-plane parity test signs with the control-plane implementation and
verifies here so the two sides cannot drift silently.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Token type identifiers (payload claim values, not secrets).
TOKEN_TYPE_MUTATION = "mutation"
TOKEN_TYPE_READ = "read"  # nosec B105


class JobTokenError(Exception):
    """Raised when a job token cannot be validated."""


def verify_job_token(
    public_key: Ed25519PublicKey,
    token: str,
    *,
    expected_operation: Optional[str] = None,
    expected_assessment_id: Optional[str] = None,
    expected_tenant_id: Optional[str] = None,
    expected_audience: Optional[str] = None,
    expected_issuer: Optional[str] = None,
) -> dict[str, Any]:
    """Verify a job capability token with the public key.

    Checks the Ed25519 signature, algorithm, expiry/not-before, and any
    expected claim bindings supplied by the caller.

    Raises:
        JobTokenError: If the token is malformed, forged, expired, or
            mismatched.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise JobTokenError("Token must have exactly 3 parts")
        header_b64, payload_b64, signature_b64 = parts

        header = json.loads(_urlsafe_b64decode(header_b64))
        payload = json.loads(_urlsafe_b64decode(payload_b64))
        signature = _urlsafe_b64decode(signature_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise JobTokenError(f"Malformed token: {exc}") from exc

    if header.get("alg") != "EdDSA":
        raise JobTokenError(f"Unsupported algorithm: {header.get('alg')}")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    try:
        public_key.verify(signature, signing_input)
    except Exception as exc:
        raise JobTokenError(f"Invalid signature: {exc}") from exc

    now = int(time.time())
    if payload.get("exp", 0) < now:
        raise JobTokenError("Token expired")
    if payload.get("nbf", 0) > now:
        raise JobTokenError("Token not yet valid")

    if expected_operation is not None and payload.get("operation") != expected_operation:
        raise JobTokenError(
            f"Operation mismatch: expected {expected_operation}, "
            f"got {payload.get('operation')}"
        )

    if (
        expected_assessment_id is not None
        and payload.get("assessment_id") != expected_assessment_id
    ):
        raise JobTokenError(
            f"Assessment mismatch: expected {expected_assessment_id}, "
            f"got {payload.get('assessment_id')}"
        )

    if (
        expected_tenant_id is not None
        and payload.get("tenant_id") != expected_tenant_id
    ):
        raise JobTokenError(
            f"Tenant mismatch: expected {expected_tenant_id}, "
            f"got {payload.get('tenant_id')}"
        )

    if expected_audience is not None and payload.get("aud") != expected_audience:
        raise JobTokenError(
            f"Audience mismatch: expected {expected_audience}, "
            f"got {payload.get('aud')}"
        )

    if expected_issuer is not None and payload.get("iss") != expected_issuer:
        raise JobTokenError(
            f"Issuer mismatch: expected {expected_issuer}, "
            f"got {payload.get('iss')}"
        )

    return payload


def _urlsafe_b64decode(data: str) -> bytes:
    if isinstance(data, str):
        data = data.encode("ascii")
    padding_bytes = b"=" * (len(data) % 4)
    return base64.urlsafe_b64decode(data + padding_bytes)
