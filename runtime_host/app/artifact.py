"""Self-contained, fail-closed artifact download and tar extraction."""

from __future__ import annotations

import hashlib
import fnmatch
import http.client
import ipaddress
import io
import os
import shutil
import socket
import ssl
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

MAX_ARTIFACT_BYTES = 500 * 1024 * 1024
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILES = 50_000
SENSITIVE_NAMES = {
    ".env", ".git", "id_rsa", "id_ed25519", "credentials", "password", "secret"
}
FORBIDDEN_TYPES = {
    tarfile.SYMTYPE,
    tarfile.LNKTYPE,
    tarfile.CHRTYPE,
    tarfile.BLKTYPE,
    tarfile.FIFOTYPE,
}


class ArtifactError(ValueError):
    """Raised when a remote artifact fails a transfer or extraction check."""


def _allowed_origins(allowlist: str | None = None) -> set[str]:
    value = allowlist if allowlist is not None else os.environ.get("RUNTIME_ARTIFACT_ORIGINS", "")
    return {host.strip().lower().rstrip(".") for host in value.split(",") if host.strip()}


def _resolve_public_ip(host: str, allowed_hosts: set[str]) -> str:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not literal.is_global:
            raise ArtifactError("Non-global artifact server address is not allowed")
        return str(literal)

    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ArtifactError("Artifact host could not be resolved") from exc
    if not addresses:
        raise ArtifactError("Artifact host has no resolved addresses")
    parsed = []
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ArtifactError("Artifact host resolved to an invalid address") from exc
        if not ip.is_global:
            raise ArtifactError("Artifact host resolved to a non-global address")
        parsed.append(str(ip))
    # Pin the connection to one of the validated addresses to prevent DNS rebinding.
    return sorted(parsed)[0]


def download_artifact(
    url: str,
    expected_sha256: str,
    *,
    allowlist: str | None = None,
    timeout_seconds: float = 60.0,
) -> bytes:
    """Download an allowlisted HTTPS artifact and verify its SHA-256 digest."""
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise ArtifactError("Only HTTPS artifact URLs are allowed")
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ArtifactError("Artifact URL is malformed or contains credentials")
    host = parsed.hostname.lower().rstrip(".")
    allowed = _allowed_origins(allowlist)
    if not allowed or host not in allowed:
        raise ArtifactError("Artifact host is not in the configured allowlist")
    if host == "169.254.169.254":
        raise ArtifactError("Cloud metadata endpoint is not allowed")
    address = _resolve_public_ip(host, allowed)
    port = parsed.port or 443
    request_path = parsed.path or "/"
    if parsed.query:
        request_path += "?" + parsed.query

    raw_socket = None
    connection = None
    try:
        raw_socket = socket.create_connection((address, port), timeout=timeout_seconds)
        tls_socket = ssl.create_default_context().wrap_socket(raw_socket, server_hostname=host)
        raw_socket = None  # TLS socket now owns the descriptor.
        connection = http.client.HTTPSConnection(address, port=port, timeout=timeout_seconds)
        connection.sock = tls_socket
        connection.request("GET", request_path, headers={"Host": host, "Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            raise ArtifactError(f"Artifact download returned HTTP {response.status}")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_ARTIFACT_BYTES:
                raise ArtifactError("Artifact exceeds the compressed size limit")
            chunks.append(chunk)
        data = b"".join(chunks)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise ArtifactError(f"Artifact download failed: {type(exc).__name__}") from exc
    finally:
        if connection is not None:
            connection.close()
        if raw_socket is not None:
            raw_socket.close()

    expected = expected_sha256.removeprefix("sha256:").lower()
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        raise ArtifactError("Expected SHA-256 claim is malformed")
    actual = hashlib.sha256(data).hexdigest()
    if not __import__("hmac").compare_digest(actual, expected):
        raise ArtifactError("Artifact SHA-256 does not match the capability claim")
    return data


def extract_artifact_safely(data: bytes, parent_dir: str | None = None) -> str:
    """Extract a verified tar.gz into a private directory without path escapes."""
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ArtifactError("Artifact exceeds the compressed size limit")
    target = tempfile.mkdtemp(prefix="runtime-artifact-", dir=parent_dir)
    root = Path(target).resolve()
    count = 0
    expanded = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or "\\" in member.name:
                    raise ArtifactError("Archive contains an absolute or traversal path")
                if member.type in FORBIDDEN_TYPES or not (member.isdir() or member.isfile()):
                    raise ArtifactError("Archive contains an unsupported member type")
                if any(
                    part.lower() in SENSITIVE_NAMES
                    or any(fnmatch.fnmatch(part.lower(), pattern) for pattern in (
                        "*.env", "*.key", "*.pem", "*.p12", "*.pfx",
                        "*secret*", "*credential*", "*password*",
                    ))
                    for part in path.parts
                ):
                    raise ArtifactError("Archive contains a sensitive file")
                if member.mode & 0o7111:
                    raise ArtifactError("Archive contains an executable or set-id file")
                destination = (root / Path(*path.parts)).resolve()
                if destination != root and root not in destination.parents:
                    raise ArtifactError("Archive member escapes extraction directory")
                count += 1
                expanded += member.size
                if count > MAX_FILES or expanded > MAX_EXPANDED_BYTES:
                    raise ArtifactError("Archive extraction limits exceeded")
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ArtifactError("Archive member could not be read")
                with source, destination.open("xb") as output:
                    shutil.copyfileobj(source, output, length=64 * 1024)
                os.chmod(destination, member.mode & 0o666)
        return str(root)
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise
