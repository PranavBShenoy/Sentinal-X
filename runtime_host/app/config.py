"""Runtime Host configuration loading and validation.

Fails closed: the service refuses to start when the public verification key,
the trusted client CA, or the trusted-proxy credentials are missing,
unreadable, or invalid.

Environment variables:
    RUNTIME_HOST_PUBLIC_KEY_PATH: Path to the Ed25519 public verification key PEM.
    RUNTIME_HOST_CLIENT_CA_PATH:  Path to the trusted client CA certificate PEM.
    RUNTIME_HOST_PROXY_TOKEN:     Shared secret injected by the trusted Nginx
                                  terminator. Required unless a token file is used.
    RUNTIME_HOST_PROXY_TOKEN_FILE: Path to a protected file containing the shared
                                  secret (Docker secret). Takes precedence over the
                                  environment variable when set.
    RUNTIME_HOST_AUDIENCE:        Expected JWT audience. Required in production.
    RUNTIME_HOST_ISSUER:          Expected JWT issuer.
    RUNTIME_HOST_PORT:            Internal Uvicorn listen port.
    APP_ENV:                      Deployment environment (production/prod
                                  enforce the audience requirement).
                                  ENVIRONMENT is accepted as a fallback.
"""
from __future__ import annotations

import os
import re
import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

DEFAULT_ISSUER = "sentinelx-authorization"
DEFAULT_PORT = 8443
MIN_PROXY_TOKEN_LENGTH = 32

# Proxy tokens are injected into an Nginx configuration file. Restrict the
# alphabet so a token can never terminate or alter that directive.
_PROXY_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")

# Public placeholders that must never be accepted as real secrets.
_PLACEHOLDER_MARKERS = (
    "CHANGE_ME",
    "CHANGEME",
    "REPLACE_ME",
    "PLACEHOLDER",
    "EXAMPLE_TOKEN",
    "YOUR_TOKEN",
)

_PRODUCTION_VALUES = {"production", "prod"}


class ConfigError(RuntimeError):
    """Raised when required Runtime Host configuration is missing or invalid."""


@dataclass(frozen=True)
class RuntimeHostConfig:
    """Validated Runtime Host startup configuration."""

    public_key_pem: bytes
    client_ca_pem: bytes
    proxy_token: str
    expected_audience: str | None
    expected_issuer: str
    port: int
    advertised_host: str
    bind_ip: str


def load_advertised_target() -> tuple[str, str]:
    """Return (advertised host, private interface IP used for Docker publish)."""
    advertised_ip = os.environ.get("RUNTIME_HOST_ADVERTISED_IP", "").strip()
    advertised_hostname = os.environ.get("ADVERTISED_HOSTNAME", "").strip().lower().rstrip(".")
    bind_ip = os.environ.get("RUNTIME_HOST_BIND_IP", "").strip()
    if advertised_ip and advertised_hostname:
        raise ConfigError("Set only one of RUNTIME_HOST_ADVERTISED_IP or ADVERTISED_HOSTNAME")

    def private_ipv4(value: str, name: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ConfigError(f"{name} must be an IPv4 address") from exc
        private_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if not isinstance(address, ipaddress.IPv4Address) or not any(address in net for net in private_networks):
            raise ConfigError(f"{name} must be an RFC1918 IPv4 address")
        return str(address)

    if advertised_ip:
        ip = private_ipv4(advertised_ip, "RUNTIME_HOST_ADVERTISED_IP")
        if bind_ip and private_ipv4(bind_ip, "RUNTIME_HOST_BIND_IP") != ip:
            raise ConfigError("RUNTIME_HOST_BIND_IP must match RUNTIME_HOST_ADVERTISED_IP")
        return ip, ip
    if advertised_hostname:
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+", advertised_hostname):
            raise ConfigError("ADVERTISED_HOSTNAME must be a fully qualified DNS hostname")
        if not bind_ip:
            raise ConfigError("RUNTIME_HOST_BIND_IP is required with ADVERTISED_HOSTNAME")
        return advertised_hostname, private_ipv4(bind_ip, "RUNTIME_HOST_BIND_IP")
    # Local development fallback retains loopback-only target publication.
    if _is_production():
        raise ConfigError(
            "RUNTIME_HOST_ADVERTISED_IP or ADVERTISED_HOSTNAME is required in production"
        )
    return "127.0.0.1", "127.0.0.1"


def _validate_public_key_pem(public_key_pem: bytes) -> None:
    """Validate that PEM bytes contain an Ed25519 public key."""
    if not public_key_pem:
        raise ConfigError("public verification key is empty")
    try:
        key = load_pem_public_key(public_key_pem)
    except Exception as exc:
        raise ConfigError(
            "public verification key is not a valid PEM public key"
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ConfigError("public verification key must be an Ed25519 key")


def load_public_key_from_path(path: str | None) -> bytes:
    """Read and validate the public verification key from a filesystem path."""
    if not path:
        raise ConfigError("RUNTIME_HOST_PUBLIC_KEY_PATH is required")

    key_path = Path(path).expanduser()
    if not key_path.is_file():
        raise ConfigError(
            f"RUNTIME_HOST_PUBLIC_KEY_PATH is not a readable file: {key_path}"
        )
    try:
        public_key_pem = key_path.read_bytes()
    except OSError as exc:
        raise ConfigError(
            f"RUNTIME_HOST_PUBLIC_KEY_PATH could not be read: {key_path}"
        ) from exc

    _validate_public_key_pem(public_key_pem)
    return public_key_pem


def validate_public_key_pem(public_key_pem: bytes) -> None:
    """Public wrapper used by the app factory for explicit PEM input."""
    _validate_public_key_pem(public_key_pem)


def _validate_ca_certificate(cert: x509.Certificate) -> None:
    """Require a currently valid CA certificate that may sign certificates."""
    try:
        constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise ConfigError(
            "trusted client CA certificate must include BasicConstraints CA:TRUE"
        ) from exc
    if not constraints.ca:
        raise ConfigError(
            "trusted client CA certificate must be a CA (BasicConstraints CA:TRUE)"
        )

    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        key_usage = None
    if key_usage is not None and not key_usage.key_cert_sign:
        raise ConfigError(
            "trusted client CA key usage must permit certificate signing"
        )

    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        not_before = cert.not_valid_before.replace(tzinfo=UTC)
        not_after = cert.not_valid_after.replace(tzinfo=UTC)

    now = datetime.now(UTC)
    if now < not_before or now > not_after:
        raise ConfigError("trusted client CA certificate is not currently valid")


def validate_client_ca_pem(client_ca_pem: bytes) -> None:
    """Validate that PEM bytes contain one or more usable CA certificates."""
    if not client_ca_pem:
        raise ConfigError("trusted client CA certificate is empty")
    try:
        certificates = x509.load_pem_x509_certificates(client_ca_pem)
    except Exception as exc:
        raise ConfigError(
            "trusted client CA certificate is not a valid PEM certificate"
        ) from exc
    if not certificates:
        raise ConfigError("trusted client CA certificate is empty")
    for cert in certificates:
        _validate_ca_certificate(cert)


def load_client_ca_from_path(path: str | None) -> bytes:
    """Read and validate the trusted client CA certificate from disk."""
    if not path:
        raise ConfigError("RUNTIME_HOST_CLIENT_CA_PATH is required")

    ca_path = Path(path).expanduser()
    if not ca_path.is_file():
        raise ConfigError(
            f"RUNTIME_HOST_CLIENT_CA_PATH is not a readable file: {ca_path}"
        )
    try:
        client_ca_pem = ca_path.read_bytes()
    except OSError as exc:
        raise ConfigError(
            f"RUNTIME_HOST_CLIENT_CA_PATH could not be read: {ca_path}"
        ) from exc

    validate_client_ca_pem(client_ca_pem)
    return client_ca_pem


def validate_proxy_token(token: str | None) -> str:
    """Validate the shared trusted-proxy token.

    Requires at least 32 characters drawn from ``[A-Za-z0-9_-]`` and rejects
    public placeholder values such as ``CHANGE_ME...``.
    """
    if not token:
        raise ConfigError("RUNTIME_HOST_PROXY_TOKEN is required")
    if len(token) < MIN_PROXY_TOKEN_LENGTH:
        raise ConfigError(
            "RUNTIME_HOST_PROXY_TOKEN must be at least "
            f"{MIN_PROXY_TOKEN_LENGTH} characters"
        )
    if not _PROXY_TOKEN_RE.fullmatch(token):
        raise ConfigError(
            "RUNTIME_HOST_PROXY_TOKEN may contain only A-Z, a-z, 0-9, '_' and '-'"
        )
    upper = token.upper()
    if any(marker in upper for marker in _PLACEHOLDER_MARKERS):
        raise ConfigError(
            "RUNTIME_HOST_PROXY_TOKEN must not contain a placeholder value"
        )
    return token


def load_proxy_token(
    token: str | None = None, token_file: str | None = None
) -> str:
    """Load the proxy token from an explicit value, a protected file, or env.

    A token file (for example a Docker secret) takes precedence over the
    environment variable. The file may end with a newline; leading/trailing
    whitespace is stripped before validation.
    """
    if token is not None:
        return validate_proxy_token(token)

    if token_file is None:
        token_file = os.environ.get("RUNTIME_HOST_PROXY_TOKEN_FILE")
    if token_file:
        path = Path(token_file).expanduser()
        if not path.is_file():
            raise ConfigError(
                "RUNTIME_HOST_PROXY_TOKEN_FILE is not a readable file: "
                f"{path}"
            )
        try:
            token = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise ConfigError(
                "RUNTIME_HOST_PROXY_TOKEN_FILE could not be read: "
                f"{path}"
            ) from exc
        return validate_proxy_token(token)

    return validate_proxy_token(os.environ.get("RUNTIME_HOST_PROXY_TOKEN"))


def _is_production() -> bool:
    """Return True when the deployment is production.

    ``APP_ENV`` is the canonical variable across SENTINEL-X services.
    ``ENVIRONMENT`` is accepted as a backwards-compatible fallback so older
    compose files or runbooks that set only ENVIRONMENT cannot silently
    downgrade production-only checks.
    """
    value = os.environ.get("APP_ENV") or os.environ.get("ENVIRONMENT", "")
    return value.strip().lower() in _PRODUCTION_VALUES


def load_config() -> RuntimeHostConfig:
    """Load and validate all Runtime Host startup configuration."""
    public_key_pem = load_public_key_from_path(
        os.environ.get("RUNTIME_HOST_PUBLIC_KEY_PATH")
    )
    client_ca_pem = load_client_ca_from_path(
        os.environ.get("RUNTIME_HOST_CLIENT_CA_PATH")
    )
    proxy_token = load_proxy_token(
        token_file=os.environ.get("RUNTIME_HOST_PROXY_TOKEN_FILE")
    )
    expected_audience = os.environ.get("RUNTIME_HOST_AUDIENCE") or None
    if expected_audience is None and _is_production():
        raise ConfigError("RUNTIME_HOST_AUDIENCE is required in production")
    expected_issuer = os.environ.get("RUNTIME_HOST_ISSUER", DEFAULT_ISSUER)

    raw_port = os.environ.get("RUNTIME_HOST_PORT", str(DEFAULT_PORT))
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise ConfigError("RUNTIME_HOST_PORT must be an integer") from exc
    if not (1 <= port <= 65535):
        raise ConfigError("RUNTIME_HOST_PORT must be between 1 and 65535")
    advertised_host, bind_ip = load_advertised_target()

    return RuntimeHostConfig(
        public_key_pem=public_key_pem,
        client_ca_pem=client_ca_pem,
        proxy_token=proxy_token,
        expected_audience=expected_audience,
        expected_issuer=expected_issuer,
        port=port,
        advertised_host=advertised_host,
        bind_ip=bind_ip,
    )
