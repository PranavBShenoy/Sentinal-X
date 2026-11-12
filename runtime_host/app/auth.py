"""
mTLS + JWT authentication for the Runtime Host.

Trust model:
- TLS terminates at the trusted Nginx proxy, which validates the client
  certificate chain against an explicitly configured CA (and optional CRL).
- Nginx injects the verified client certificate (URL-encoded PEM) and a shared
  proxy token. It strips caller-supplied identity headers first.
- The Runtime Host accepts identity only when the trusted proxy token matches,
  and derives the worker's SHA-256 fingerprint from the DER certificate.
- As defense-in-depth, the Runtime Host also verifies the forwarded leaf
  certificate chains to the configured client CA and requires clientAuth EKU.
- The certificate subject is audit metadata only; it is never the identity key.

JWT verification is unchanged: Ed25519 signature, expiry (exp/nbf), audience
(aud), issuer (iss), required claims, and replay prevention for mutation tokens.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from datetime import UTC, datetime
from urllib.parse import unquote

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509.oid import ExtendedKeyUsageOID
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import ConfigError, validate_proxy_token
from .nonce_store import NonceStore
from .token_verification import JobTokenError, verify_job_token

logger = logging.getLogger(__name__)

# Durable nonce store for replay prevention (mutation tokens only).
# Survives Runtime Host restarts via SQLite.
_nonce_store = NonceStore()
NONCE_CACHE_TTL_SECONDS = 300  # 5 minutes

# Bound the amount of certificate material parsed per request and the length
# of an intermediate chain accepted from the trusted proxy.
MAX_CERT_HEADER_BYTES = 32 * 1024
MAX_CHAIN_DEPTH = 4

_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_FINGERPRINT_NORMALIZE_RE = re.compile(r"[\s:\-]")

_bearer = HTTPBearer(auto_error=False)


def _cleanup_nonce_cache() -> int:
    """Remove expired nonces from the durable store."""
    return _nonce_store.cleanup_expired(NONCE_CACHE_TTL_SECONDS)


def _check_replay(jti: str) -> None:
    """Atomically consume a nonce (replay prevention).

    Raises HTTPException if the jti has already been consumed.
    """
    _cleanup_nonce_cache()
    if not _nonce_store.consume(jti, NONCE_CACHE_TTL_SECONDS):
        logger.warning("Replay detected for jti: %s", jti)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Job token already used (replay detected)",
        )


def _load_public_key(pem_bytes: bytes):
    """Load an Ed25519 public key from PEM bytes."""
    return load_pem_public_key(pem_bytes)


def normalize_fingerprint(value: str) -> str:
    """Normalize a SHA-256 fingerprint to 64 lowercase hex characters.

    Accepts common presentation formats with colons, whitespace, or hyphens.
    """
    return _FINGERPRINT_NORMALIZE_RE.sub("", value).lower()


def validate_fingerprint(value: str) -> str:
    """Return a normalized fingerprint or raise ValueError if malformed."""
    normalized = normalize_fingerprint(value)
    if not _FINGERPRINT_RE.fullmatch(normalized):
        raise ValueError(
            "certificate fingerprint must be exactly 64 hexadecimal characters"
        )
    return normalized


def _certificate_validity(cert: x509.Certificate) -> None:
    """Defense-in-depth check for certificate validity period.

    Nginx already rejects expired/not-yet-valid certificates during the TLS
    handshake; this check keeps the Runtime Host fail-closed if it is ever
    reached through a misconfigured proxy.
    """
    now = datetime.now(UTC)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        not_before = cert.not_valid_before.replace(tzinfo=UTC)
        not_after = cert.not_valid_after.replace(tzinfo=UTC)

    if now < not_before:
        raise ValueError("client certificate is not yet valid")
    if now > not_after:
        raise ValueError("client certificate has expired")


def _is_ca_certificate(cert: x509.Certificate) -> bool:
    """Return True when the certificate asserts the CA basic constraint."""
    try:
        constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound:
        return False
    return bool(constraints.ca)


def _check_leaf_certificate(cert: x509.Certificate) -> None:
    """Validate certificate purpose for a worker/client identity."""
    _certificate_validity(cert)

    if _is_ca_certificate(cert):
        raise ValueError(
            "client certificate must not be a CA certificate"
        )

    try:
        eku = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound as exc:
        raise ValueError(
            "client certificate must include clientAuth extended key usage"
        ) from exc
    if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
        raise ValueError(
            "client certificate extended key usage must include clientAuth"
        )

    try:
        key_usage = cert.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value
    except x509.ExtensionNotFound:
        key_usage = None
    if key_usage is not None and not key_usage.digital_signature:
        raise ValueError(
            "client certificate key usage must permit digital signatures"
        )


def _check_intermediate_certificate(cert: x509.Certificate) -> None:
    """Validate an untrusted intermediate CA in the forwarded chain."""
    _certificate_validity(cert)
    if not _is_ca_certificate(cert):
        raise ValueError("intermediate certificate must be a CA")

    try:
        key_usage = cert.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value
    except x509.ExtensionNotFound:
        key_usage = None
    if key_usage is not None and not key_usage.key_cert_sign:
        raise ValueError(
            "intermediate CA key usage must permit certificate signing"
        )


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Return True when ``issuer`` directly signed ``cert``."""
    try:
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def _parse_client_ca(client_ca_pem: bytes) -> tuple[x509.Certificate, ...]:
    """Parse and sanity-check the trusted client CA bundle."""
    try:
        certificates = x509.load_pem_x509_certificates(client_ca_pem)
    except Exception as exc:
        raise ValueError(
            "client CA certificate is not valid PEM"
        ) from exc
    if not certificates:
        raise ValueError("client CA certificate is empty")
    for cert in certificates:
        if not _is_ca_certificate(cert):
            raise ValueError(
                "client CA certificate must be a CA "
                "(BasicConstraints CA:TRUE)"
            )
    return tuple(certificates)


def _constant_time_token_match(supplied: str | None, expected: str | None) -> bool:
    """Constant-time comparison that cannot raise on non-ASCII input."""
    if not supplied or not expected:
        return False
    try:
        return secrets.compare_digest(
            supplied.encode("utf-8"), expected.encode("utf-8")
        )
    except UnicodeError:
        return False


class Authenticator:
    """Verifies a trusted-proxy client certificate identity and job token.

    Requires a valid JWT public verification key at construction. When mTLS is
    enabled, a proxy token and trusted client CA are also required so the
    Runtime Host can distinguish requests from the trusted Nginx terminator and
    independently verify the forwarded certificate chain.
    """

    def __init__(
        self,
        public_key_pem: bytes,
        expected_audience: str | None = None,
        require_mtls: bool = True,
        expected_issuer: str = "sentinelx-authorization",
        proxy_token: str | None = None,
        client_ca_pem: bytes | None = None,
        proxy_header: str = "X-Runtime-Proxy-Token",
        client_cert_header: str = "X-Client-Cert",
        client_fingerprint_header: str = "X-Client-Cert-SHA256",
    ) -> None:
        if not public_key_pem:
            raise ValueError("public_key_pem is required to construct Authenticator")
        self._public_key = _load_public_key(public_key_pem)
        self._expected_audience = expected_audience
        self._require_mtls = require_mtls
        self._expected_issuer = expected_issuer
        self._proxy_header = proxy_header
        self._client_cert_header = client_cert_header
        self._client_fingerprint_header = client_fingerprint_header

        if require_mtls:
            if not proxy_token:
                raise ValueError(
                    "proxy_token is required when mTLS is enabled"
                )
            try:
                validate_proxy_token(proxy_token)
            except ConfigError as exc:
                raise ValueError(str(exc)) from exc
            if not client_ca_pem:
                raise ValueError(
                    "client_ca_pem is required when mTLS is enabled"
                )
            self._client_ca_certs = _parse_client_ca(client_ca_pem)
        else:
            self._client_ca_certs = ()
        self._proxy_token = proxy_token

    def _verify_certificate_chain(
        self,
        leaf: x509.Certificate,
        intermediates: list[x509.Certificate],
    ) -> None:
        """Verify the leaf chains to a trusted client CA.

        Nginx already performs this verification during the TLS handshake; this
        is defense-in-depth so the Runtime Host fails closed on its own. The
        walk is bounded, rejects CA certificates as leaves, requires the
        clientAuth EKU, and validates every certificate's dates.
        """
        _check_leaf_certificate(leaf)

        if len(intermediates) > MAX_CHAIN_DEPTH:
            raise ValueError("client certificate chain is too long")

        remaining = list(intermediates)
        current = leaf
        for _ in range(MAX_CHAIN_DEPTH + 1):
            for anchor in self._client_ca_certs:
                if _issued_by(current, anchor):
                    _certificate_validity(anchor)
                    if not _is_ca_certificate(anchor):
                        raise ValueError("trust anchor is not a CA")
                    return

            issuer_index = next(
                (
                    index
                    for index, candidate in enumerate(remaining)
                    if candidate.subject == current.issuer
                    and _issued_by(current, candidate)
                ),
                None,
            )
            if issuer_index is None:
                raise ValueError(
                    "client certificate is not issued by a trusted CA"
                )

            current = remaining.pop(issuer_index)
            _check_intermediate_certificate(current)

        raise ValueError("client certificate chain is too long")

    def _extract_certificate(self, request: Request) -> x509.Certificate:
        """Parse and verify the Nginx-verified client certificate header.

        The header contains a URL-encoded PEM certificate set by the trusted
        proxy. Caller-supplied legacy headers are ignored entirely.
        """
        raw_cert = request.headers.get(self._client_cert_header)
        if not raw_cert:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Client certificate required",
            )
        if len(raw_cert) > MAX_CERT_HEADER_BYTES:
            logger.warning(
                "mTLS authentication failed: client certificate header too large"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client certificate",
            )

        try:
            pem = unquote(raw_cert).strip()
            certificates = x509.load_pem_x509_certificates(pem.encode("utf-8"))
        except Exception as exc:
            logger.warning("mTLS authentication failed: malformed client certificate")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client certificate",
            ) from exc

        if not certificates:
            logger.warning("mTLS authentication failed: empty client certificate")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client certificate",
            )

        leaf = certificates[0]
        try:
            self._verify_certificate_chain(leaf, list(certificates[1:]))
        except ValueError as exc:
            logger.warning("mTLS authentication failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client certificate",
            ) from exc

        return leaf

    def _verify_proxy_identity(self, request: Request) -> tuple[str, str]:
        """Return (sha256_fingerprint, subject) for a trusted proxy request."""
        proxy_token = request.headers.get(self._proxy_header)
        if not _constant_time_token_match(proxy_token, self._proxy_token):
            logger.warning(
                "mTLS authentication failed: missing or invalid proxy token"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Trusted proxy authentication required",
            )

        cert = self._extract_certificate(request)
        der = cert.public_bytes(serialization.Encoding.DER)
        fingerprint = hashlib.sha256(der).hexdigest()

        # If a trusted proxy also supplies a fingerprint, validate and require
        # it to match the certificate actually received. Never trust it alone.
        supplied = request.headers.get(self._client_fingerprint_header)
        if supplied:
            try:
                supplied_fingerprint = validate_fingerprint(supplied)
            except ValueError as exc:
                logger.warning(
                    "mTLS authentication failed: malformed fingerprint header"
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid client certificate fingerprint",
                ) from exc

            if not secrets.compare_digest(
                supplied_fingerprint.encode("ascii"),
                fingerprint.encode("ascii"),
            ):
                logger.warning(
                    "mTLS authentication failed: certificate fingerprint mismatch"
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Client certificate fingerprint mismatch",
                )

        subject = cert.subject.rfc4514_string()
        logger.info(
            "mTLS client certificate authenticated",
            extra={"worker_fingerprint_prefix": fingerprint[:12]},
        )
        return fingerprint, subject

    async def authenticate(
        self,
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = None,
    ) -> AuthContext:
        """Authenticate a request: trusted-proxy mTLS identity + JWT token.

        Returns an AuthContext on success.
        Raises HTTPException on any authentication failure.
        """
        worker_fingerprint: str | None = None
        worker_cert_subject: str | None = None

        if self._require_mtls:
            worker_fingerprint, worker_cert_subject = self._verify_proxy_identity(
                request
            )

        if credentials is None:
            credentials = await _bearer(request)

        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing job capability token",
            )

        token = credentials.credentials
        try:
            payload = verify_job_token(
                self._public_key,
                token,
                expected_issuer=self._expected_issuer,
                expected_audience=self._expected_audience,
            )
        except JobTokenError as exc:
            logger.warning("Job token verification failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid job token: {exc}",
            ) from exc

        # Extract claims
        jti = payload.get("jti")
        tenant_id = payload.get("tenant_id")
        assessment_id = payload.get("assessment_id")
        job_id = payload.get("job_id")
        operation = payload.get("operation")
        token_type = payload.get("token_type")
        resources = payload.get("resources", [])
        resource_limits = payload.get("resource_limits", {})
        aud = payload.get("aud")

        if not all(
            [jti, tenant_id, assessment_id, job_id, operation, token_type]
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Job token missing required claims",
            )

        # Replay prevention for mutation tokens (one-time use)
        if token_type == "mutation":  # nosec B105: "mutation" is a JWT token type identifier, not a password/secret
            _check_replay(jti)

        # Read tokens are reusable within TTL; no replay cache enforced
        return AuthContext(
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            job_id=job_id,
            operation=operation,
            jti=jti,
            token_type=token_type,
            resources=resources,
            resource_limits=resource_limits,
            aud=aud,
            worker_fingerprint=worker_fingerprint,
            worker_cert_subject=worker_cert_subject,
        )


class AuthContext:
    """Authenticated request context populated by authentication."""

    def __init__(
        self,
        *,
        tenant_id: str,
        assessment_id: str,
        job_id: str,
        operation: str,
        jti: str,
        token_type: str,
        resources: list[str],
        resource_limits: dict,
        aud: str | None,
        worker_fingerprint: str | None = None,
        worker_cert_subject: str | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.assessment_id = assessment_id
        self.job_id = job_id
        self.operation = operation
        self.jti = jti
        self.token_type = token_type
        self.resources = resources
        self.resource_limits = resource_limits
        self.aud = aud
        self.worker_fingerprint = worker_fingerprint
        self.worker_cert_subject = worker_cert_subject


def require_mutation(auth: AuthContext = Depends(lambda: None)) -> AuthContext:  # noqa: B008
    """Dependency that requires a mutation-type token."""
    if auth is None or auth.token_type != "mutation":  # nosec B105: "mutation" is a JWT token type identifier, not a password/secret
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Mutation token required for this operation",
        )
    return auth


def require_read(auth: AuthContext = Depends(lambda: None)) -> AuthContext:  # noqa: B008
    """Dependency that requires a read-type token."""
    if auth is None or auth.token_type != "read":  # nosec B105: "read" is a JWT token type identifier, not a password/secret
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Read token required for this operation",
        )
    return auth
