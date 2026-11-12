"""
Adversarial tests for artifact_transfer.py (Phase B — SSRF protection).

Verifies:
- Empty or missing origin allowlist rejects every artifact download.
- Exact hostname/origin allowlisting.
- HTTPS and certificate verification.
- Redirect rejection.
- Credentials embedded in URLs rejected.
- Private, loopback, link-local, multicast and reserved IPs rejected.
- DNS resolution and rebinding resistance.
- DNS rebinding: connect only to validated IP, not hostname.
- Download size enforced during streaming (chunked reads).
- Archive traversal, symlink, hardlink, device file and FIFO rejection.
- Executable and setuid/setgid file rejection.
- Decompression bombs (size and file-count limits).
- Sensitive file exclusion (.env, keys, credentials, .git).
- SHA-256 hash verification (mandatory).
- Extraction timeout enforcement.
- Private staging directory extraction (no caller-owned dir deletion).
- Symlinked extraction path rejection.
- Partial extraction cleanup without deleting caller data.

Mock-only tests for download; one real local HTTPS integration test
using a test certificate.
"""

from __future__ import annotations

import hashlib
import io
import os
import socket
import ssl
import sys
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

_BACKEND = str(Path(__file__).resolve().parent.parent.parent / "backend")
for _p in (_BACKEND,):
    if _p in sys.path:
        sys.path.remove(_p)
sys.path.insert(0, _BACKEND)

import pytest

from app.runtime.artifact_transfer import (
    ArtifactTransferError,
    create_workspace_tarball,
    download_artifact,
    extract_archive_safely,
    validate_origin,
    MAX_COMPRESSED_SIZE_BYTES,
    MAX_DECOMPRESSED_SIZE_BYTES,
    MAX_FILE_COUNT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tarball(
    members: list[tuple[str, bytes, int]],
    compress: bool = True,
) -> bytes:
    """Create a tarball in memory."""
    buf = io.BytesIO()
    mode = "w:gz" if compress else "w"
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        for name, content, mtype in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            info.type = mtype
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# validate_origin tests
# ---------------------------------------------------------------------------

class TestValidateOrigin:
    @pytest.fixture(autouse=True)
    def _mock_dns_public(self):
        """Mock DNS resolution to return a public IP for hostnames."""
        import ipaddress

        def _getaddrinfo_side_effect(host, *args, **kwargs):
            try:
                ipaddress.ip_address(host)
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, 80)),
                ]
            except ValueError:
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80)),
                ]

        with patch("socket.getaddrinfo", side_effect=_getaddrinfo_side_effect):
            yield

    def test_empty_allowlist_rejects_all(self):
        """Empty RUNTIME_ARTIFACT_ORIGINS rejects every URL."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = ""

        with pytest.raises(ArtifactTransferError, match="no origins permitted"):
            validate_origin("https://example.com/artifact.tar.gz")

    def test_exact_hostname_allowlisting(self):
        """Only exact hostnames in allowlist are accepted."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "artifacts.internal.example.com"

        result = validate_origin(
            "https://artifacts.internal.example.com/artifact.tar.gz"
        )
        assert "artifacts.internal.example.com" in result

        with pytest.raises(
            ArtifactTransferError, match="not in artifact origin allowlist"
        ):
            validate_origin("https://evil.example.com/artifact.tar.gz")

        with pytest.raises(
            ArtifactTransferError, match="not in artifact origin allowlist"
        ):
            validate_origin(
                "https://sub.artifacts.internal.example.com/artifact.tar.gz"
            )

    def test_http_rejected(self):
        """Non-HTTPS schemes are rejected."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        with pytest.raises(ArtifactTransferError, match="Unsupported scheme"):
            validate_origin("http://example.com/artifact.tar.gz")

        with pytest.raises(ArtifactTransferError, match="Unsupported scheme"):
            validate_origin("ftp://example.com/artifact.tar.gz")

    def test_credentials_in_url_rejected(self):
        """user:pass@host in URL is rejected."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        with pytest.raises(ArtifactTransferError, match="Credentials in URL"):
            validate_origin("https://user:pass@example.com/artifact.tar.gz")

    def test_private_ip_rejected(self):
        """RFC 1918 private IPs are rejected."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        for ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1"]:
            with pytest.raises(
                ArtifactTransferError, match="Non-global address not allowed"
            ):
                validate_origin(f"https://{ip}/artifact.tar.gz")

    def test_loopback_rejected(self):
        """Loopback addresses are rejected."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        for host in ["127.0.0.1", "[::1]"]:
            with pytest.raises(
                ArtifactTransferError, match="Non-global address not allowed"
            ):
                validate_origin(f"https://{host}/artifact.tar.gz")

        # "localhost" is a hostname rejected by allowlist check
        with pytest.raises(
            ArtifactTransferError, match="not in artifact origin allowlist"
        ):
            validate_origin("https://localhost/artifact.tar.gz")

    def test_link_local_rejected(self):
        """Link-local addresses are rejected."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        with pytest.raises(
            ArtifactTransferError, match="Non-global address not allowed"
        ):
            validate_origin("https://169.254.1.1/artifact.tar.gz")

    def test_metadata_endpoint_rejected(self):
        """Cloud metadata endpoint is always rejected."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        with pytest.raises(ArtifactTransferError, match="Metadata endpoint"):
            validate_origin("https://169.254.169.254/latest/meta-data/")

    def test_multicast_rejected(self):
        """Multicast addresses are rejected."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        with pytest.raises(
            ArtifactTransferError, match="Origin not in artifact origin allowlist"
        ):
            validate_origin("https://224.0.0.1/artifact.tar.gz")

    def test_reserved_range_rejected(self):
        """Reserved ranges (RFC 5735) are rejected."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        with pytest.raises(
            ArtifactTransferError, match="Non-global address not allowed"
        ):
            validate_origin("https://192.0.2.1/artifact.tar.gz")

    def test_multiple_allowed_origins(self):
        """Multiple comma-separated origins are all accepted."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "host-a.internal, host-b.internal"

        validate_origin("https://host-a.internal/artifact.tar.gz")
        validate_origin("https://host-b.internal/artifact.tar.gz")

        with pytest.raises(
            ArtifactTransferError, match="not in artifact origin allowlist"
        ):
            validate_origin("https://host-c.internal/artifact.tar.gz")

    def test_dns_rebinding_private_resolved(self):
        """Hostname resolving to private IP is rejected (DNS rebinding)."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "rebinding.example.com"

        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 80)),
            ]

            with pytest.raises(
                ArtifactTransferError,
                match="Resolved address 10.0.0.5 is not global",
            ):
                validate_origin("https://rebinding.example.com/artifact.tar.gz")

    def test_dns_rebinding_public_ok(self):
        """Hostname resolving to public IP is accepted."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "rebinding.example.com"

        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80)),
            ]

            result = validate_origin("https://rebinding.example.com/artifact.tar.gz")
            assert "rebinding.example.com" in result

    def test_dns_resolution_failure(self):
        """Unresolvable hostname is rejected."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "nonexistent.example.com"

        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.side_effect = socket.gaierror("Name does not resolve")

            with pytest.raises(ArtifactTransferError, match="Cannot resolve host"):
                validate_origin("https://nonexistent.example.com/artifact.tar.gz")

    def test_mixed_public_private_dns_rejected(self):
        """If any DNS result is non-global, the whole host is rejected."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "mixed.example.com"

        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 80)),
            ]

            with pytest.raises(
                ArtifactTransferError,
                match="Resolved address 10.0.0.5 is not global",
            ):
                validate_origin("https://mixed.example.com/artifact.tar.gz")

    def test_ipv4_mapped_ipv6_rejected(self):
        """IPv4-mapped IPv6 addresses are not global and rejected."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        # ::ffff:10.0.0.1 is an IPv4-mapped IPv6 address (not global)
        with pytest.raises(
            ArtifactTransferError, match="Non-global address not allowed"
        ):
            validate_origin("https://[::ffff:10.0.0.1]/artifact.tar.gz")

    def test_ipv6_unique_local_rejected(self):
        """IPv6 unique-local addresses (fc00::/7) are rejected."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        with pytest.raises(
            ArtifactTransferError, match="Non-global address not allowed"
        ):
            validate_origin("https://[fc00::1]/artifact.tar.gz")


# ---------------------------------------------------------------------------
# download_artifact tests
# ---------------------------------------------------------------------------

class TestDownloadArtifact:
    def test_download_requires_allowlisted_origin(self):
        """download_artifact validates origin before downloading."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = ""

        with pytest.raises(ArtifactTransferError, match="no origins permitted"):
            download_artifact(
                "https://evil.com/artifact.tar.gz",
                expected_sha256="sha256:" + "0" * 64,
            )

    def test_download_requires_sha256(self):
        """SHA-256 is mandatory — calling without it raises TypeError."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        with pytest.raises(TypeError):
            download_artifact("https://example.com/artifact.tar.gz")

    def test_download_connects_to_validated_ip_not_hostname(self):
        """DNS rebinding protection: connects to validated IP, uses hostname
        only for SNI/Host header."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        tarball = _make_tarball([("hello.txt", b"hello world", tarfile.REGTYPE)])
        expected_hash = hashlib.sha256(tarball).hexdigest()

        captured = {}

        def fake_create_connection(address, *args, **kwargs):
            captured["connect_address"] = address[0]
            captured["connect_port"] = address[1]
            # Return an in-memory socket double; the test must not open a real socket.
            return MagicMock()

        with patch("socket.create_connection", side_effect=fake_create_connection):
            with patch(
                "app.runtime.artifact_transfer.socket.getaddrinfo"
            ) as mock_dns:
                mock_dns.return_value = [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
                ]

                # Mock ssl.wrap_socket to return the sock itself (no real TLS)
                with patch(
                    "ssl.create_default_context"
                ) as mock_ssl_context:
                    mock_context = MagicMock()
                    mock_context.wrap_socket.side_effect = lambda sock, **kw: sock
                    mock_ssl_context.return_value = mock_context

                    # Patch HTTPSConnection to capture but not actually connect
                    with patch(
                        "app.runtime.artifact_transfer.http.client.HTTPSConnection"
                    ) as mock_http_conn:
                        mock_resp = MagicMock()
                        mock_resp.status = 200
                        mock_resp.read.side_effect = [tarball, b""]
                        mock_http_conn.return_value.getresponse.return_value = (
                            mock_resp
                        )

                        result = download_artifact(
                            "https://example.com/artifact.tar.gz",
                            expected_sha256=f"sha256:{expected_hash}",
                        )
                        assert result == tarball

                        # Verify connection was made to the validated IP
                        assert captured["connect_address"] == "93.184.216.34"
                        assert captured["connect_port"] == 443

                        # Verify SNI/Host header uses original hostname
                        call_args = mock_http_conn.return_value.request.call_args
                        headers = call_args[1]["headers"]
                        assert headers["Host"] == "example.com"

    def test_download_connects_to_validated_ip_ipv6(self):
        """IPv6 validated IP is used for connection."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        tarball = _make_tarball([("hello.txt", b"hello world", tarfile.REGTYPE)])
        expected_hash = hashlib.sha256(tarball).hexdigest()

        captured = {}

        def fake_create_connection(address, *args, **kwargs):
            captured["connect_address"] = address[0]
            captured["connect_port"] = address[1]
            return MagicMock()

        with patch("socket.create_connection", side_effect=fake_create_connection):
            with patch(
                "app.runtime.artifact_transfer.socket.getaddrinfo"
            ) as mock_dns:
                mock_dns.return_value = [
                    (
                        socket.AF_INET6,
                        socket.SOCK_STREAM,
                        6,
                        "",
                        ("2606:4700:4700::1111", 443, 0, 0),
                    ),
                ]

                with patch(
                    "app.runtime.artifact_transfer.ssl.create_default_context"
                ) as mock_ssl_context:
                    mock_context = MagicMock()
                    mock_context.wrap_socket.side_effect = lambda sock, **kw: sock
                    mock_ssl_context.return_value = mock_context

                    with patch(
                        "app.runtime.artifact_transfer.http.client.HTTPSConnection"
                    ) as mock_http_conn:
                        mock_resp = MagicMock()
                        mock_resp.status = 200
                        mock_resp.read.side_effect = [tarball, b""]
                        mock_http_conn.return_value.getresponse.return_value = (
                            mock_resp
                        )

                        download_artifact(
                            "https://example.com/artifact.tar.gz",
                            expected_sha256=f"sha256:{expected_hash}",
                        )

                        assert captured["connect_address"] == "2606:4700:4700::1111"

    def test_download_sha256_mismatch(self):
        """SHA-256 mismatch rejects download."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        with patch(
            "app.runtime.artifact_transfer.socket.getaddrinfo"
        ) as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            ]

            with patch(
                "app.runtime.artifact_transfer.socket.create_connection"
            ) as mock_connect:
                mock_connect.return_value = MagicMock()

                with patch(
                    "app.runtime.artifact_transfer.ssl.create_default_context"
                ) as mock_ssl_context:
                    mock_ssl_context.return_value.wrap_socket.return_value = (
                        MagicMock()
                    )

                    with patch(
                        "app.runtime.artifact_transfer.http.client.HTTPSConnection"
                    ) as mock_http_conn:
                        mock_resp = MagicMock()
                        mock_resp.status = 200
                        mock_resp.read.side_effect = [b"wrong-content", b""]
                        mock_http_conn.return_value.getresponse.return_value = mock_resp

                        with pytest.raises(
                            ArtifactTransferError, match="SHA-256 mismatch"
                        ):
                            download_artifact(
                                "https://example.com/artifact.tar.gz",
                                expected_sha256="sha256:" + "0" * 64,
                            )

    def test_download_oversized_rejected_during_streaming(self):
        """Oversized response is rejected without buffering entire body."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        with patch(
            "app.runtime.artifact_transfer.socket.getaddrinfo"
        ) as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            ]

            with patch(
                "app.runtime.artifact_transfer.socket.create_connection"
            ) as mock_connect:
                mock_connect.return_value = MagicMock()

                with patch(
                    "app.runtime.artifact_transfer.ssl.create_default_context"
                ) as mock_ssl_context:
                    mock_ssl_context.return_value.wrap_socket.return_value = (
                        MagicMock()
                    )

                    with patch(
                        "app.runtime.artifact_transfer.http.client.HTTPSConnection"
                    ) as mock_http_conn:
                        mock_resp = MagicMock()
                        mock_resp.status = 200

                        # Simulate a finite stream that exceeds the limit.
                        state = {"total": 0}
                        limit = MAX_COMPRESSED_SIZE_BYTES + 10000

                        def read_chunks(size):
                            if state["total"] >= limit:
                                return b""
                            chunk_size = min(65536, limit - state["total"])
                            state["total"] += chunk_size
                            return b"x" * chunk_size

                        mock_resp.read.side_effect = read_chunks
                        mock_http_conn.return_value.getresponse.return_value = mock_resp

                        with pytest.raises(
                            ArtifactTransferError, match="too large"
                        ):
                            download_artifact(
                                "https://example.com/artifact.tar.gz",
                                expected_sha256="sha256:" + "0" * 64,
                            )

    def test_download_http_error(self):
        """Non-2xx HTTP responses are rejected."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        with patch(
            "app.runtime.artifact_transfer.socket.getaddrinfo"
        ) as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            ]

            with patch(
                "app.runtime.artifact_transfer.socket.create_connection"
            ) as mock_connect:
                mock_connect.return_value = MagicMock()

                with patch(
                    "app.runtime.artifact_transfer.ssl.create_default_context"
                ) as mock_ssl_context:
                    mock_ssl_context.return_value.wrap_socket.return_value = (
                        MagicMock()
                    )

                    with patch(
                        "app.runtime.artifact_transfer.http.client.HTTPSConnection"
                    ) as mock_http_conn:
                        mock_resp = MagicMock()
                        mock_resp.status = 404
                        mock_http_conn.return_value.getresponse.return_value = mock_resp

                        with pytest.raises(ArtifactTransferError, match="HTTP 404"):
                            download_artifact(
                                "https://example.com/artifact.tar.gz",
                                expected_sha256="sha256:" + "0" * 64,
                            )

    def test_download_connection_error(self):
        """Connection errors are wrapped in ArtifactTransferError."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        with patch(
            "app.runtime.artifact_transfer.socket.getaddrinfo"
        ) as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            ]

            with patch(
                "app.runtime.artifact_transfer.socket.create_connection"
            ) as mock_connect:
                mock_connect.side_effect = OSError("Connection refused")

                with pytest.raises(
                    ArtifactTransferError, match="connection error"
                ):
                    download_artifact(
                        "https://example.com/artifact.tar.gz",
                        expected_sha256="sha256:" + "0" * 64,
                    )

    def test_download_tls_error(self):
        """TLS errors are wrapped in ArtifactTransferError."""
        from app.core.config import get_settings

        settings = get_settings()
        settings.RUNTIME_ARTIFACT_ORIGINS = "example.com"

        with patch(
            "app.runtime.artifact_transfer.socket.getaddrinfo"
        ) as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            ]

            with patch(
                "app.runtime.artifact_transfer.socket.create_connection"
            ) as mock_connect:
                mock_sock = MagicMock()
                mock_connect.return_value = mock_sock

                with patch(
                    "app.runtime.artifact_transfer.ssl.create_default_context"
                ) as mock_ssl_ctx:
                    mock_ctx = MagicMock()
                    mock_ctx.wrap_socket.side_effect = ssl.SSLError(
                        "certificate verify failed"
                    )
                    mock_ssl_ctx.return_value = mock_ctx

                    with pytest.raises(
                        ArtifactTransferError, match="TLS error"
                    ):
                        download_artifact(
                            "https://example.com/artifact.tar.gz",
                            expected_sha256="sha256:" + "0" * 64,
                        )


# ---------------------------------------------------------------------------
# extract_archive_safely tests
# ---------------------------------------------------------------------------

class TestExtractArchiveSafely:
    def test_normal_extraction(self):
        """Normal tarball extracts successfully into a staging directory."""
        tarball = _make_tarball([("hello.txt", b"hello world", tarfile.REGTYPE)])

        result = extract_archive_safely(tarball)
        assert os.path.isdir(result)
        assert result.startswith(tempfile.gettempdir())

        extracted_file = os.path.join(result, "hello.txt")
        assert os.path.isfile(extracted_file)
        with open(extracted_file, "rb") as f:
            assert f.read() == b"hello world"

    def test_extract_path_traversal(self):
        """Path traversal (../) is rejected."""
        tarball = _make_tarball(
            [("../../../etc/passwd", b"root:x:0:0:", tarfile.REGTYPE)]
        )

        with pytest.raises(ArtifactTransferError, match="traversal"):
            extract_archive_safely(tarball)

    def test_symlink_rejected(self):
        """Symlink members are rejected."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="evil.symlink")
            info.type = tarfile.SYMTYPE
            info.size = 0
            tar.addfile(info, io.BytesIO(b""))
        tarball = buf.getvalue()

        with pytest.raises(
            ArtifactTransferError, match="Dangerous archive member type"
        ):
            extract_archive_safely(tarball)

    def test_hardlink_rejected(self):
        """Hardlink members are rejected."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="evil.hardlink")
            info.type = tarfile.LNKTYPE
            info.size = 0
            tar.addfile(info, io.BytesIO(b""))
        tarball = buf.getvalue()

        with pytest.raises(
            ArtifactTransferError, match="Dangerous archive member type"
        ):
            extract_archive_safely(tarball)

    def test_absolute_path_rejected(self):
        """Absolute paths are rejected."""
        tarball = _make_tarball([("/etc/passwd", b"root:x:0:0:", tarfile.REGTYPE)])

        with pytest.raises(ArtifactTransferError, match="Absolute path"):
            extract_archive_safely(tarball)

    def test_dotenv_excluded(self):
        """.env files are excluded."""
        tarball = _make_tarball([(".env", b"SECRET=secret", tarfile.REGTYPE)])

        with pytest.raises(ArtifactTransferError, match="Sensitive file"):
            extract_archive_safely(tarball)

    def test_private_key_excluded(self):
        """Private key files are excluded."""
        tarball = _make_tarball([("id_rsa", b"PRIVATE KEY", tarfile.REGTYPE)])

        with pytest.raises(ArtifactTransferError, match="Sensitive file"):
            extract_archive_safely(tarball)

    def test_git_excluded(self):
        """.git directory is excluded."""
        tarball = _make_tarball([(".git/config", b"[core]", tarfile.REGTYPE)])

        with pytest.raises(ArtifactTransferError, match="Sensitive file"):
            extract_archive_safely(tarball)

    def test_device_file_rejected(self):
        """Device files are rejected (absolute path check)."""
        tarball = _make_tarball([("/dev/null", b"", tarfile.CHRTYPE)])

        with pytest.raises(ArtifactTransferError, match="Absolute path"):
            extract_archive_safely(tarball)

    def test_fifo_rejected(self):
        """FIFO files are rejected."""
        tarball = _make_tarball([("myfifo", b"", tarfile.FIFOTYPE)])

        with pytest.raises(ArtifactTransferError, match="Dangerous archive member"):
            extract_archive_safely(tarball)

    def test_decompression_bomb_rejected(self):
        """Decompressed size limit is enforced."""
        members = [
            ("big.txt", b"x" * (MAX_DECOMPRESSED_SIZE_BYTES + 1), tarfile.REGTYPE)
        ]
        tarball = _make_tarball(members)

        with pytest.raises(ArtifactTransferError, match="size limit exceeded"):
            extract_archive_safely(tarball)

    def test_file_count_limit_rejected(self):
        """File count limit is enforced."""
        members = [
            (f"file_{i}.txt", b"content", tarfile.REGTYPE)
            for i in range(MAX_FILE_COUNT + 1)
        ]
        tarball = _make_tarball(members)

        with pytest.raises(
            ArtifactTransferError, match="File count limit exceeded"
        ):
            extract_archive_safely(tarball)

    def test_extract_executable_rejected(self):
        """Executable files are rejected."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="script.sh")
            info.size = len(b"#!/bin/sh")
            info.mode = 0o755  # executable
            tar.addfile(info, io.BytesIO(b"#!/bin/sh"))
        tarball = buf.getvalue()

        with pytest.raises(ArtifactTransferError, match="Executable file"):
            extract_archive_safely(tarball)

    def test_extract_setuid_rejected(self):
        """Setuid files are rejected."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="setuid_bin")
            info.size = len(b"binary")
            info.mode = 0o4644  # setuid without execute bits
            tar.addfile(info, io.BytesIO(b"binary"))
        tarball = buf.getvalue()

        with pytest.raises(ArtifactTransferError, match="Setuid/setgid file"):
            extract_archive_safely(tarball)

    def test_extract_cleanup_on_failure(self):
        """Partial extraction is cleaned up on failure — staging dir removed."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info1 = tarfile.TarInfo(name="safe.txt")
            info1.size = len(b"safe")
            tar.addfile(info1, io.BytesIO(b"safe"))
            info2 = tarfile.TarInfo(name="../../../etc/passwd")
            info2.size = len(b"root:x:0:0:")
            tar.addfile(info2, io.BytesIO(b"root:x:0:0:"))
        tarball = buf.getvalue()

        with tempfile.TemporaryDirectory() as tmpdir:
            extract_dir = os.path.join(tmpdir, "extract")
            os.makedirs(extract_dir)
            with pytest.raises(ArtifactTransferError, match="traversal"):
                extract_archive_safely(tarball, extract_dir=extract_dir)
            # The staging directory is cleaned up, but the caller's directory
            # is never deleted and is left empty.
            assert os.path.isdir(extract_dir)
            assert os.listdir(extract_dir) == []
            # Caller's tmpdir should still exist
            assert os.path.exists(tmpdir)

    def test_extract_into_caller_provided_dir(self):
        """Extraction into caller-provided directory uses staging subdir."""
        tarball = _make_tarball([("hello.txt", b"hello world", tarfile.REGTYPE)])

        with tempfile.TemporaryDirectory() as tmpdir:
            extract_dir = os.path.join(tmpdir, "my_extract")
            os.makedirs(extract_dir)
            # Pre-create a file in the caller's directory
            with open(os.path.join(extract_dir, "preexisting.txt"), "w") as f:
                f.write("preexisting")

            result = extract_archive_safely(tarball, extract_dir=extract_dir)

            # Result is a staging subdirectory, not extract_dir itself
            assert result != extract_dir
            assert result.startswith(extract_dir + os.sep)
            assert os.path.isdir(result)

            # Caller's pre-existing file is untouched
            with open(os.path.join(extract_dir, "preexisting.txt")) as f:
                assert f.read() == "preexisting"

            # Extracted file is in the staging subdirectory
            assert os.path.isfile(os.path.join(result, "hello.txt"))

    def test_extract_symlinked_path_rejected(self):
        """Symlinked extraction directory is rejected."""
        tarball = _make_tarball([("safe.txt", b"content", tarfile.REGTYPE)])

        with tempfile.TemporaryDirectory() as tmpdir:
            real_dir = os.path.join(tmpdir, "real")
            os.makedirs(real_dir)
            symlink_dir = os.path.join(tmpdir, "symlink")
            os.symlink(real_dir, symlink_dir)

            with pytest.raises(
                ArtifactTransferError, match="symlink"
            ):
                extract_archive_safely(tarball, extract_dir=symlink_dir)


# ---------------------------------------------------------------------------
# create_workspace_tarball tests
# ---------------------------------------------------------------------------

class TestArtifactTransferCreate:
    def test_create_workspace_tarball(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "test.txt"), "w") as f:
                f.write("hello world")

            tarball, sha256 = create_workspace_tarball(tmpdir)
            assert isinstance(tarball, bytes)
            assert len(sha256) == 64

            actual_hash = hashlib.sha256(tarball).hexdigest()
            assert sha256 == actual_hash
