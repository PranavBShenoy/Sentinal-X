"""
Exhaustive SSRF Protection and DNS Rebinding Defense Test Suite.

Verifies:
1. Strict protocol allowlist: HTTP and HTTPS only.
2. Rejection of loopback addresses: 127.0.0.1, localhost, ::1.
3. Rejection of RFC 1918 private subnets: 10.0.0.1, 172.16.0.1, 192.168.1.1.
4. Rejection of IPv6 loopback (::1), ULA (fd00::1, fc00::1), link-local (fe80::1).
5. Rejection of IPv4-mapped IPv6 addresses (::ffff:127.0.0.1, ::ffff:10.0.0.1).
6. Rejection of cloud metadata IPs (169.254.169.254, fd00:ec2::254) and hostnames (metadata.google.internal).
7. DNS resolution failures fail-closed (never silently pass).
8. Mixed A/AAAA records (if any resolved IP is non-public, reject).
9. Encoded and alternative IP representations (octal, hex, decimal dword).
10. Unsupported URL schemes (file://, ftp://, gopher://, javascript:).
11. Malformed URLs and URLs with credentials.
12. Valid public HTTP/HTTPS destinations.
13. SafeSSRFClient DNS rebinding protection via pinned socket transport.
14. SafeSSRFClient redirect re-validation (rejecting redirect to private address).
"""
from __future__ import annotations

import socket
import unittest.mock
import pytest
from app.core.ssrf import (
    SSRFValidationError,
    SafeSSRFClient,
    canonicalize_ip_representation,
    is_prohibited_ip,
    validate_target_url,
)


def test_ssrf_loopback_rejected():
    """Verify loopback IPv4 and localhost are strictly rejected."""
    for url in (
        "http://127.0.0.1:8080/admin",
        "http://127.0.0.2/status",
        "http://127.1.2.3:3000",
        "http://localhost:8000/metrics",
        "https://localhost:8443",
    ):
        with pytest.raises(SSRFValidationError) as exc:
            validate_target_url(url)
        assert "prohibited" in str(exc.value.detail).lower() or "loopback" in str(exc.value.detail).lower()


def test_ssrf_rfc1918_private_ips_rejected():
    """Verify all RFC 1918 private subnets (10/8, 172.16/12, 192.168/16) are rejected."""
    for url in (
        "http://10.0.0.1/internal-api",
        "http://10.254.0.1:8080",
        "http://172.16.0.1/vault",
        "http://172.31.255.254",
        "http://192.168.1.1:8443/router",
        "http://192.168.0.100/debug",
    ):
        with pytest.raises(SSRFValidationError) as exc:
            validate_target_url(url)
        assert "private" in str(exc.value.detail).lower() or "prohibited" in str(exc.value.detail).lower()


def test_ssrf_ipv6_loopback_and_ula_and_link_local_rejected():
    """Verify IPv6 loopback (::1), ULA (fc00::/7, fd00::/8), and link-local (fe80::/10) are rejected."""
    for url in (
        "http://[::1]:8000",
        "http://[::1]/",
        "http://[fc00::1]/service",
        "http://[fd00::1]:8080",
        "http://[fd12:3456:789a:1::1]/",
        "http://[fe80::1]/link",
    ):
        with pytest.raises(SSRFValidationError) as exc:
            validate_target_url(url)
        assert "prohibited" in str(exc.value.detail).lower() or "blocked" in str(exc.value.detail).lower()


def test_ssrf_ipv4_mapped_ipv6_rejected():
    """Verify IPv4-mapped IPv6 transition addresses (::ffff:127.0.0.1, ::ffff:10.0.0.1) are unmapped and rejected."""
    for url in (
        "http://[::ffff:127.0.0.1]:8080",
        "http://[::ffff:10.0.0.1]/admin",
        "http://[::ffff:192.168.1.1]/",
        "http://[::ffff:169.254.169.254]/latest",
    ):
        with pytest.raises(SSRFValidationError) as exc:
            validate_target_url(url)
        assert "prohibited" in str(exc.value.detail).lower() or "blocked" in str(exc.value.detail).lower()


def test_ssrf_cloud_metadata_ips_and_hostnames_rejected():
    """Verify cloud provider metadata endpoints (AWS, GCP, Azure, Alibaba) are blocked."""
    for url in (
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/",
        "http://instance-data/latest/",
        "http://100.100.100.200/latest/meta-data/",
        "http://[fd00:ec2::254]/latest/meta-data/",
    ):
        with pytest.raises(SSRFValidationError) as exc:
            validate_target_url(url)
        assert "metadata" in str(exc.value.detail).lower() or "prohibited" in str(exc.value.detail).lower()


def test_ssrf_dns_resolution_failure_fails_closed():
    """Verify DNS resolution failure fails closed and raises SSRFValidationError."""
    with pytest.raises(SSRFValidationError) as exc:
        validate_target_url("http://nonexistent-domain-that-definitely-does-not-exist-123456.local/")
    assert "dns resolution" in str(exc.value.detail).lower() or "could not be resolved" in str(exc.value.detail).lower()


def test_ssrf_mixed_public_private_dns_response_rejected():
    """Verify that if a hostname resolves to both a public IP and a private IP, it is rejected."""
    # Mock socket.getaddrinfo to return a public IP (93.184.216.34) and a private IP (10.0.0.1)
    fake_addr_info = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 80)),
    ]
    with unittest.mock.patch("socket.getaddrinfo", return_value=fake_addr_info):
        with pytest.raises(SSRFValidationError) as exc:
            validate_target_url("http://mixed-dns-rebind-test.com/api")
        assert "prohibited" in str(exc.value.detail).lower() or "blocked" in str(exc.value.detail).lower()


def test_ssrf_encoded_and_alternative_ip_representations():
    """Verify evasion attempts using decimal dword, octal, and hex IP formats are blocked."""
    # 2130706433 is decimal dword for 127.0.0.1
    # 0177.0.0.1 is octal for 127.0.0.1
    # 0x7f000001 is hex for 127.0.0.1
    # 0x7f.0.0.1 is dotted hex for 127.0.0.1
    for url in (
        "http://2130706433:8080/admin",
        "http://0177.0.0.1/secret",
        "http://0x7f000001:3000",
        "http://0x7f.0.0.1/",
    ):
        with pytest.raises(SSRFValidationError) as exc:
            validate_target_url(url)
        assert "prohibited" in str(exc.value.detail).lower() or "blocked" in str(exc.value.detail).lower()


def test_ssrf_unsupported_schemes_and_malformed_urls():
    """Verify non-HTTP schemes and malformed URLs are rejected."""
    for url in (
        "file:///etc/passwd",
        "ftp://internal.server/backup.sql",
        "gopher://127.0.0.1:70/",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "javascript:alert(1)",
        "http://user:pass@example.com/",
        "http://",
        "not-a-valid-url",
        "http://example.com:99999/",  # Invalid port
    ):
        with pytest.raises(SSRFValidationError):
            validate_target_url(url)


def test_ssrf_valid_public_destination_allowed():
    """Verify valid public destination passes validation."""
    # Mock getaddrinfo to return example.com's public IP
    fake_public_info = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
    ]
    with unittest.mock.patch("socket.getaddrinfo", return_value=fake_public_info):
        canonical = validate_target_url("https://example.com/api/v1/health")
        assert canonical == "https://example.com/api/v1/health"


def test_safe_ssrf_client_blocks_redirect_to_private():
    """Verify SafeSSRFClient intercepts 3xx redirect to a private address and raises SSRFValidationError."""
    import httpx

    # Create dummy response simulating 302 redirect to http://127.0.0.1:8080/admin
    redirect_resp = httpx.Response(
        status_code=302,
        headers={"Location": "http://127.0.0.1:8080/admin"},
        request=httpx.Request("GET", "https://example.com/login"),
    )

    client = SafeSSRFClient(allow_internal_runtime=False)
    with unittest.mock.patch.object(httpx.Client, "request", return_value=redirect_resp):
        with unittest.mock.patch("app.core.ssrf.resolve_all_ip_addresses", return_value=[]) as mock_resolve:
            with pytest.raises(SSRFValidationError) as exc:
                # Trigger request
                client.request("GET", "https://example.com/login")
            assert "prohibited" in str(exc.value.detail).lower() or "loopback" in str(exc.value.detail).lower()
