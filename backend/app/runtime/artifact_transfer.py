"""
Secure artifact transfer for SENTINEL-X Runtime Execution Plane.

Handles workspace tarball creation, SHA-256 verification, and safe archive
extraction on the Runtime Host. All operations treat the tarball as hostile
input and enforce strict security limits.

Security controls:
- Origin allowlisting for artifact download URLs
- HTTPS only; no automatic redirects
- DNS/IP validation and SSRF prevention
- DNS rebinding protection: connects to validated IP only with single TLS
  handshake using original hostname for SNI and certificate verification
- Download size enforced during streaming (chunked reads)
- Decompressed size, file-count, and extraction-timeout limits
- Safe tar extraction into a private staging directory with no caller-owned
  directory deletion
- Executable and setuid/setgid file rejection
- Exclusion of .env, private keys, credentials, .git, and platform secrets
- Content hash verification (SHA-256, mandatory)
- Never logs pre-signed URLs or credentials in full
- Partial extraction cleanup on failure
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import io
import logging
import os
import signal
import socket
import ssl
import tarfile
import tempfile
from typing import Optional
from urllib.parse import urlparse

from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security limits
# ---------------------------------------------------------------------------

MAX_COMPRESSED_SIZE_BYTES = 500 * 1024 * 1024  # 500 MB
MAX_DECOMPRESSED_SIZE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB
MAX_FILE_COUNT = 50_000
EXTRACTION_TIMEOUT_SECONDS = 120

# Patterns for sensitive files that must be excluded from extraction
SENSITIVE_NAME_PATTERNS = (
    ".env",
    "*.env",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "id_rsa",
    "id_ed25519",
    "*secret*",
    "*credential*",
    "*password*",
    ".git",
)

# Dangerous tar member types
DANGEROUS_TYPES = {
    tarfile.SYMTYPE,   # symlink
    tarfile.LNKTYPE,   # hardlink
    tarfile.CHRTYPE,   # character device
    tarfile.BLKTYPE,   # block device
    tarfile.FIFOTYPE,  # FIFO
}


def _is_global_ip(host: str) -> bool:
    """Check if a literal IP address is globally routable.

    Rejects every non-global IP address, including:
    - Loopback: 127.0.0.0/8, ::1/128
    - Link-local: 169.254.0.0/16, fe80::/10
    - Private (RFC 1918): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    - Carrier-grade NAT: 100.64.0.0/10
    - Reserved (RFC 5735, RFC 6890): documentation, multicast, etc.
    - Unique-local IPv6: fc00::/7
    - IPv4-mapped IPv6: ::ffff:0:0:0/96
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Not a literal IP — caller must handle hostname resolution separately
        return False

    # is_global() returns True only for globally routable unicast addresses
    # It excludes loopback, link-local, private, reserved, multicast, etc.
    return ip.is_global


def _resolve_and_validate_host(host: str, allowed_origins: list[str]) -> None:
    """Resolve a hostname via DNS and validate all resolved IPs.

    Protects against DNS rebinding by ensuring all resolved addresses are
    global (not private/reserved) unless explicitly allowlisted.
    """
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC)
    except socket.gaierror:
        raise ArtifactTransferError(f"Cannot resolve host: {host}")

    resolved_ips = set()
    for info in infos:
        addr = info[4][0]
        resolved_ips.add(addr)

    if not resolved_ips:
        raise ArtifactTransferError(f"No addresses resolved for {host}")

    for ip_str in resolved_ips:
        if not _is_global_ip(ip_str) and ip_str not in allowed_origins:
            raise ArtifactTransferError(
                f"Resolved address {ip_str} is not global and not allowlisted"
            )


def _resolve_validated_ip(url: str) -> tuple[str, str]:
    """Resolve the URL hostname to a validated global IP address.

    Resolves DNS, validates all resolved IPs are global, and returns the
    first validated IP along with the original hostname.

    Returns:
        (ip_address, original_hostname)

    Raises:
        ArtifactTransferError: If DNS resolution fails or all resolved IPs
            are non-global.
    """
    parsed = urlparse(url)
    host = parsed.hostname.lower()

    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC)
    except socket.gaierror:
        raise ArtifactTransferError(f"Cannot resolve host: {host}")

    resolved_ips = []
    for info in infos:
        addr = info[4][0]
        resolved_ips.append(addr)

    if not resolved_ips:
        raise ArtifactTransferError(f"No addresses resolved for {host}")

    for ip_str in resolved_ips:
        if not _is_global_ip(ip_str):
            raise ArtifactTransferError(
                f"Resolved address {ip_str} is not global"
            )

    # Return the first validated global IP
    return resolved_ips[0], host


class ArtifactTransferError(Exception):
    """Raised when artifact transfer or extraction fails."""


def _is_sensitive_member(name: str) -> bool:
    """Check if a tar member name matches a sensitive pattern."""
    import fnmatch

    base = os.path.basename(name)
    parts = name.replace("\\", "/").split("/")
    for pattern in SENSITIVE_NAME_PATTERNS:
        if fnmatch.fnmatch(base, pattern) or fnmatch.fnmatch(name, pattern):
            return True
        if ".git" in parts:
            return True
    return False


def _validate_member(member: tarfile.TarInfo, extract_dir: str) -> None:
    """Validate a single tar member for safety.

    Raises ArtifactTransferError if the member is unsafe.
    """
    name = member.name

    # Reject absolute paths
    if os.path.isabs(name):
        raise ArtifactTransferError(
            f"Absolute path in archive: {name}"
        )

    # Reject path traversal
    extract_dir_norm = os.path.normpath(extract_dir)
    resolved = os.path.normpath(os.path.join(extract_dir, name))
    if not resolved.startswith(extract_dir_norm + os.sep) and resolved != extract_dir_norm:
        raise ArtifactTransferError(
            f"Path traversal in archive: {name}"
        )

    # Reject dangerous types
    if member.type in DANGEROUS_TYPES:
        raise ArtifactTransferError(
            f"Dangerous archive member type {member.type}: {name}"
        )

    # Reject sensitive files
    if _is_sensitive_member(name):
        raise ArtifactTransferError(
            f"Sensitive file excluded from archive: {name}"
        )


def _compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()


def _verify_sha256(data: bytes, expected_sha256: str) -> None:
    """Verify SHA-256 hash of data matches expected value.

    expected_sha256 may be prefixed with "sha256:".
    """
    expected = expected_sha256
    if expected.startswith("sha256:"):
        expected = expected[len("sha256:"):]
    actual = _compute_sha256(data)
    if actual != expected.lower():
        raise ArtifactTransferError(
            f"SHA-256 mismatch: expected {expected}, got {actual}"
        )


def validate_origin(url: str) -> str:
    """Validate that a URL's origin is in the allowlist.

    Returns the parsed URL if valid. Raises ArtifactTransferError otherwise.

    Security controls:
    - HTTPS only
    - No credentials in URL (user:pass@host)
    - Exact hostname allowlisting (including port if present)
    - Empty allowlist rejects ALL origins (fail closed)
    - Non-global IPs rejected unless explicitly allowlisted
    - DNS rebinding protection via resolution check
    - Metadata endpoint (169.254.169.254) always rejected
    """
    parsed = urlparse(url)

    # Only HTTPS allowed
    if parsed.scheme != "https":
        raise ArtifactTransferError(
            f"Unsupported scheme: {parsed.scheme}. Only https:// is allowed."
        )

    # Reject credentials embedded in URL
    if parsed.username or parsed.password:
        raise ArtifactTransferError("Credentials in URL not allowed")

    # Host must be present
    if not parsed.hostname:
        raise ArtifactTransferError("URL missing hostname")

    host = parsed.hostname.lower()

    # Get allowed origins (exact hostnames)
    allowed_origins = [
        o.strip().lower()
        for o in (settings.RUNTIME_ARTIFACT_ORIGINS or "").split(",")
        if o.strip()
    ]

    # Empty allowlist rejects ALL origins (fail closed)
    if not allowed_origins:
        raise ArtifactTransferError(
            "Artifact origin allowlist is empty — no origins permitted"
        )

    # Reject metadata endpoint always (even if allowlisted)
    if host == "169.254.169.254":
        raise ArtifactTransferError("Metadata endpoint access denied")

    # Reject literal non-global IPs unless explicitly allowlisted. Hostnames
    # are not IP literals: they are governed by the exact allowlist check and
    # the DNS resolution check below, so they must not be reported as
    # non-global addresses.
    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None
    if (
        literal_ip is not None
        and not literal_ip.is_global
        and host not in allowed_origins
    ):
        raise ArtifactTransferError(
            f"Non-global address not allowed: {host}"
        )

    # Exact hostname match against allowlist
    if host not in allowed_origins:
        raise ArtifactTransferError(
            f"Origin not in artifact origin allowlist: {host}"
        )

    # DNS rebinding protection: resolve and validate all resolved IPs
    _resolve_and_validate_host(host, allowed_origins)

    return url


def download_artifact(
    url: str,
    expected_sha256: str,
    timeout_seconds: float = 60.0,
) -> bytes:
    """Download an artifact from an allowlisted origin.

    Enforces:
    - HTTPS only
    - No automatic redirects
    - Origin allowlisting
    - SSRF prevention
    - DNS rebinding protection: connects to validated IP with single TLS
      handshake using original hostname for SNI and certificate verification
    - Maximum compressed size enforced during streaming (chunked reads)
    - Mandatory SHA-256 verification

    Args:
        url: The HTTPS URL to download from.
        expected_sha256: Required SHA-256 hex digest of the expected content.
            Must be provided; download fails if hash doesn't match.
        timeout_seconds: Per-request timeout in seconds.

    Returns:
        The raw tarball bytes.

    Raises:
        ArtifactTransferError: On any validation, download, or hash failure.
    """
    validate_origin(url)

    # Resolve DNS and validate IP -- prevents DNS rebinding by ensuring we
    # connect to the same IP we validated.
    target_ip, original_host = _resolve_validated_ip(url)

    parsed = urlparse(url)
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    conn: Optional[http.client.HTTPSConnection] = None
    try:
        # Create a raw TCP connection to the validated IP address.
        sock = socket.create_connection((target_ip, port), timeout=timeout_seconds)

        # Wrap in TLS with original hostname for SNI + certificate verification.
        # Exactly one TLS handshake is performed.
        context = ssl.create_default_context()
        wrapped_sock = context.wrap_socket(
            sock,
            server_hostname=original_host,
        )

        # Build an HTTPSConnection around the pre-wrapped socket so that
        # connect() is not called again (no double TLS handshake).
        conn = http.client.HTTPSConnection(target_ip, port=port)
        conn.sock = wrapped_sock

        # Send HTTP request with original hostname as Host header
        conn.request(
            "GET",
            path,
            headers={"Host": original_host, "Connection": "close"},
        )

        resp = conn.getresponse()

        if resp.status >= 300:
            conn.close()
            raise ArtifactTransferError(
                f"Artifact download failed: HTTP {resp.status}"
            )

        # Stream the response body with enforced size limit.
        chunks: list[bytes] = []
        total_read = 0
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total_read += len(chunk)
            if total_read > MAX_COMPRESSED_SIZE_BYTES:
                conn.close()
                raise ArtifactTransferError(
                    f"Artifact too large: exceeded {MAX_COMPRESSED_SIZE_BYTES} bytes"
                )
            chunks.append(chunk)

        data = b"".join(chunks)
        conn.close()
        conn = None

    except http.client.HTTPException as exc:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                # nosec B110: pass-only cleanup; outer except re-raises original error
                pass
        raise ArtifactTransferError(
            f"Artifact download HTTP error: {exc}"
        ) from exc
    except ssl.SSLError as exc:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                # nosec B11: pass-only cleanup; outer except re-raises original error
                pass
        raise ArtifactTransferError(
            f"Artifact download TLS error: {exc}"
        ) from exc
    except OSError as exc:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                # nosec B110: pass-only cleanup; outer except re-raises original error
                pass
        raise ArtifactTransferError(
            f"Artifact download connection error: {exc}"
        ) from exc

    # SHA-256 verification is mandatory
    _verify_sha256(data, expected_sha256)

    logger.info(
        "Artifact downloaded successfully",
        extra={"url_hash": hashlib.sha256(url.encode()).hexdigest()[:16], "size": len(data)},
    )
    return data


def extract_archive_safely(
    tarball_bytes: bytes,
    extract_dir: Optional[str] = None,
) -> str:
    """Extract a tarball safely with strict security limits.

    Extracts into a newly created private staging directory inside
    ``extract_dir`` (or a fresh temp directory if ``extract_dir`` is None).
    Never recursively deletes a caller-owned or pre-existing directory on
    failure — only the staging subdirectory is removed.

    Args:
        tarball_bytes: Raw tarball bytes.
        extract_dir: Parent directory for the staging directory. If None,
            a fresh temp directory is created.

    Returns the extraction directory path.
    Raises ArtifactTransferError on any safety violation, timeout, or
    if partial extraction needs cleanup.
    """
    if extract_dir is None:
        # Create a fresh private staging directory
        staging_dir = tempfile.mkdtemp(prefix="runtime-artifact-")
    else:
        # Reject symlinked extraction paths to prevent filesystem escape
        if os.path.islink(extract_dir):
            raise ArtifactTransferError(
                f"Extraction path is a symlink: {extract_dir}"
            )
        # Create a unique staging subdirectory inside the caller's directory
        staging_dir = tempfile.mkdtemp(
            prefix="runtime-artifact-", dir=extract_dir
        )

    os.makedirs(staging_dir, exist_ok=True)

    decompressed_size = 0
    file_count = 0

    # Extraction timeout handler
    def _timeout_handler(signum, frame):
        raise ArtifactTransferError(
            f"Extraction timeout exceeded: {EXTRACTION_TIMEOUT_SECONDS} seconds"
        )

    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(EXTRACTION_TIMEOUT_SECONDS)

    try:
        with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
            for member in tar.getmembers():
                # Validate member safety before extraction
                _validate_member(member, staging_dir)

                # Reject executable or setuid/setgid files
                mode = member.mode
                if mode & 0o111:
                    raise ArtifactTransferError(
                        f"Executable file rejected: {member.name}"
                    )
                if mode & 0o6000:
                    raise ArtifactTransferError(
                        f"Setuid/setgid file rejected: {member.name}"
                    )

                # Track decompressed size
                decompressed_size += member.size
                if decompressed_size > MAX_DECOMPRESSED_SIZE_BYTES:
                    raise ArtifactTransferError(
                        f"Decompressed size limit exceeded: {decompressed_size} bytes"
                    )

                # Track file count
                file_count += 1
                if file_count > MAX_FILE_COUNT:
                    raise ArtifactTransferError(
                        f"File count limit exceeded: {file_count} files"
                    )

                # Extract the member into the staging directory
                tar.extract(member, staging_dir)

        logger.info(
            "Archive extracted safely",
            extra={"files": file_count, "decompressed_bytes": decompressed_size},
        )
        return staging_dir

    except Exception:
        # Clean up only the staging directory on any failure — never delete
        # a caller-owned directory.
        import shutil

        shutil.rmtree(staging_dir, ignore_errors=True)
        raise
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def create_workspace_tarball(workspace_path: str) -> tuple[bytes, str]:
    """Create a SHA-256-verified tarball of a workspace directory.

    Args:
        workspace_path: Path to the workspace directory.

    Returns:
        (tarball_bytes, sha256_hex) -- the tarball bytes and its SHA-256 digest.
    Raises ArtifactTransferError if the workspace cannot be read.
    """
    workspace_path = os.path.abspath(workspace_path)
    if not os.path.isdir(workspace_path):
        raise ArtifactTransferError(f"Workspace not found: {workspace_path}")

    buf = io.BytesIO()
    compressed_size = 0
    file_count = 0

    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for root, dirs, files in os.walk(workspace_path):
            # Skip .git directory
            dirs[:] = [d for d in dirs if d != ".git"]

            for fname in files:
                full_path = os.path.join(root, fname)
                arcname = os.path.relpath(full_path, workspace_path)

                # Skip sensitive files
                if _is_sensitive_member(arcname):
                    continue

                # Skip symlinks
                if os.path.islink(full_path):
                    continue

                try:
                    tar.add(full_path, arcname=arcname)
                    file_count += 1
                except (OSError, tarfile.TarError):
                    continue

                # Check compressed size incrementally
                compressed_size = buf.tell()
                if compressed_size > MAX_COMPRESSED_SIZE_BYTES:
                    raise ArtifactTransferError(
                        f"Workspace tarball too large: {compressed_size} bytes"
                    )

    tarball_bytes = buf.getvalue()
    sha256_hex = _compute_sha256(tarball_bytes)

    logger.info(
        "Workspace tarball created",
        extra={"files": file_count, "size": len(tarball_bytes), "sha256": sha256_hex[:16]},
    )
    return tarball_bytes, sha256_hex
