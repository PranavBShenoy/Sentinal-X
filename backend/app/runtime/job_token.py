"""
Job capability token issuance and validation (asymmetric).

SENTINEL-X uses **asymmetric signing** for job capability tokens:

- The **Authorization Component** holds the **private signing key** and issues
  tokens after verifying assessment ownership in its database.
- The **Runtime Host** holds only the **public verification key** and verifies
  incoming tokens. It never sees the private key.
- The **Control Plane** (worker/API) requests tokens from the Authorization
  Component and presents them to the Runtime Host.

Token payload binds:
  - ``jti``: unique job ID (replay prevention)
  - ``tenant_id``: owning tenant
  - ``assessment_id``: owning assessment
  - ``job_id``: unique job identifier
  - ``operation``: ``build`` | ``run`` | ``cleanup``
  - ``resources``: exact resource names this job may touch
  - ``resource_limits``: memory, CPU, PIDs, disk, time limits
  - ``exp``: short expiry
  - ``nbf``: not-before
  - ``iat``: issued-at
  - ``iss``: ``sentinelx-authorization``

Two token types:
  - **mutation**: ``build``, ``run``, ``cleanup``, ``cancel`` — one-time use
    (``jti`` consumed once, nonce cache prevents replay).
  - **read**: ``status``, ``logs`` — re-usable within TTL for polling.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Token type constants
TOKEN_TYPE_MUTATION = "mutation"
TOKEN_TYPE_READ = "read"

# Token lifetime in seconds
MUTATION_TOKEN_TTL_SECONDS = 300  # 5 minutes
READ_TOKEN_TTL_SECONDS = 900  # 15 minutes


class JobTokenError(Exception):
    """Raised when a job token cannot be created or validated."""


def sign_job_token(
    private_key: Ed25519PrivateKey,
    *,
    jti: str,
    tenant_id: str,
    assessment_id: str,
    job_id: str,
    operation: str,
    resources: list[str],
    resource_limits: Dict[str, Any],
    token_type: str = TOKEN_TYPE_MUTATION,
    ttl_seconds: int = MUTATION_TOKEN_TTL_SECONDS,
    audience: Optional[str] = None,
    issuer: str = "sentinelx-authorization",
) -> str:
    """Sign a job capability token with the private key.

    Only the Authorization Component should call this. The Runtime Host and
    Control Plane workers never hold the private key.

    Args:
        private_key: Ed25519 private key held only by the Authorization
            Component.
        jti: Unique job ID (nonce, replay prevention).
        tenant_id: Owning tenant ID.
        assessment_id: Owning assessment ID.
        job_id: Unique job identifier.
        operation: One of ``build``, ``run``, ``cleanup``, ``cancel``
            (mutation) or ``status``, ``logs`` (read).
        resources: Exact resource names this job may touch, derived by the
            Authorization Component from ``assessment_id``.
        resource_limits: Resource limits enforced for this job.
        token_type: ``mutation`` (one-time) or ``read`` (re-usable).
        ttl_seconds: Token lifetime in seconds.
        audience: Intended audience (runtime host identifier). If set,
            included as the ``aud`` claim and verified by the Runtime Host.
        issuer: Token issuer. Defaults to ``sentinelx-authorization``.
            Verified by the Runtime Host via ``expected_issuer``.

    Returns:
        A compact JWS string (header.payload.signature).
    """
    now = int(time.time())
    payload: Dict[str, Any] = {
        "jti": jti,
        "tenant_id": tenant_id,
        "assessment_id": assessment_id,
        "job_id": job_id,
        "operation": operation,
        "resources": resources,
        "resource_limits": resource_limits,
        "exp": now + ttl_seconds,
        "nbf": now,
        "iat": now,
        "iss": issuer,
        "token_type": token_type,
    }
    if audience:
        payload["aud"] = audience

    header = {"alg": "EdDSA", "typ": "JWT"}
    header_b64 = _urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = header_b64 + b"." + payload_b64
    signature = private_key.sign(signing_input)
    signature_b64 = _urlsafe_b64encode(signature)
    return f"{header_b64.decode()}.{payload_b64.decode()}.{signature_b64.decode()}"


def verify_job_token(
    public_key: Ed25519PublicKey,
    token: str,
    *,
    expected_operation: Optional[str] = None,
    expected_assessment_id: Optional[str] = None,
    expected_tenant_id: Optional[str] = None,
    expected_audience: Optional[str] = None,
    expected_issuer: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a job capability token with the public key.

    The Runtime Host calls this on every job submission. It never has access
    to the private signing key.

    Args:
        public_key: Ed25519 public key held by the Runtime Host.
        token: Compact JWS string.
        expected_operation: If set, reject tokens with a different operation.
        expected_assessment_id: If set, reject tokens for a different
            assessment (cross-tenant protection).
        expected_tenant_id: If set, reject tokens for a different tenant.
        expected_audience: If set, reject tokens issued for a different
            audience (runtime host identifier).
        expected_issuer: If set, reject tokens issued by a different issuer.

    Returns:
        The decoded token payload dict.

    Raises:
        JobTokenError: If the token is invalid, expired, or mismatched.
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

    if expected_assessment_id is not None and payload.get("assessment_id") != expected_assessment_id:
        raise JobTokenError(
            f"Assessment mismatch: expected {expected_assessment_id}, "
            f"got {payload.get('assessment_id')}"
        )

    if expected_tenant_id is not None and payload.get("tenant_id") != expected_tenant_id:
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


def _urlsafe_b64encode(data: bytes) -> bytes:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _urlsafe_b64decode(data: str) -> bytes:
    import base64

    if isinstance(data, str):
        data = data.encode("ascii")
    padding_bytes = b"=" * (len(data) % 4)
    return base64.urlsafe_b64decode(data + padding_bytes)


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 key pair.

    The private key must be stored only by the Authorization Component.
    The public key is distributed to Runtime Hosts.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key: Ed25519PrivateKey) -> bytes:
    """Serialize a private key to PEM bytes for storage."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_public_key(public_key: Ed25519PublicKey) -> bytes:
    """Serialize a public key to PEM bytes for distribution to Runtime Hosts."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_private_key(data: bytes) -> Ed25519PrivateKey:
    """Deserialize a private key from PEM bytes (Authorization Component only)."""
    return serialization.load_pem_private_key(data, password=None)


def deserialize_public_key(data: bytes) -> Ed25519PublicKey:
    """Deserialize a public key from PEM bytes (Runtime Host)."""
    return serialization.load_pem_public_key(data)
