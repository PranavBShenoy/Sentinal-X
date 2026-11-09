"""
SENTINEL-X Comprehensive SSRF Protection Engine & Safe HTTP Transport.

Defends against Server-Side Request Forgery (SSRF), DNS rebinding, IP evasion,
protocol abuse, and redirect attacks.

Mandatory security guarantees:
1. Strict protocol allowlisting: HTTP and HTTPS only.
2. Complete non-public IP rejection:
   - Loopback (IPv4 127.0.0.0/8, IPv6 ::1/128)
   - RFC 1918 Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - IPv6 Unique Local Addresses (fc00::/7, including fd00::/8)
   - Link-Local (169.254.0.0/16, fe80::/10) - includes AWS/Azure/GCP metadata 169.254.169.254
   - Unspecified addresses (0.0.0.0/8, ::/128)
   - Multicast (224.0.0.0/4, ff00::/8)
   - Reserved & Future Use (240.0.0.0/4, 100::/64)
   - Carrier-Grade NAT / Shared Address Space (100.64.0.0/10)
   - Documentation & Benchmark subnets (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15, 2001:db8::/32)
   - AWS IPv6 Metadata (fd00:ec2::254)
   - Non-globally routable addresses (!ip.is_global)
3. IPv4-mapped IPv6 address unmapping (::ffff:127.0.0.1 -> 127.0.0.1) and transition handling.
4. Alternative IP encoding canonicalization: decimal dword, octal, hex representations.
5. Dual-stack DNS resolution: resolves all A and AAAA records. If ANY record is non-public, reject.
6. Fail-closed on DNS resolution failures or unresolvable hostnames.
7. DNS Rebinding Defense: Pinned IP socket transport guarantees the validated IP is the
   exact IP connected to at the TCP layer, preserving Host header and TLS SNI verification.
8. Redirect Validation: Automatic redirects disabled; every 3xx redirect destination is re-validated.
9. Enforced connection (5s) and read (10s) timeouts.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import urllib.parse
from typing import Any, List, Optional, Set, Tuple

import httpcore
import httpx
from fastapi import HTTPException, status

from app.core.logging import get_logger

logger = get_logger(__name__)

# Cloud metadata and internal hostnames explicitly blocked
BLOCKED_METADATA_HOSTNAMES: Set[str] = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "metadata.aws",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
}

# Explicit special-range prohibited networks
PROHIBITED_NETWORKS = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),         # Private-use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space / CGNAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # Private-use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation / TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast (RFC 7526)
    ipaddress.ip_network("192.168.0.0/16"),     # Private-use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation / TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation / TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast (RFC 919)
    # IPv6
    ipaddress.ip_network("::/128"),             # Unspecified (RFC 4291)
    ipaddress.ip_network("::1/128"),            # Loopback (RFC 4291)
    ipaddress.ip_network("100::/64"),           # Discard-Only (RFC 6666)
    ipaddress.ip_network("2001::/23"),          # IETF Protocol Assignments (RFC 2928)
    ipaddress.ip_network("2001:2::/48"),        # Benchmarking (RFC 5180)
    ipaddress.ip_network("2001:db8::/32"),      # Documentation (RFC 3849)
    ipaddress.ip_network("2001:10::/28"),       # ORCHIDv2 (RFC 7343)
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address ULA (RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast (RFC 4291)
    ipaddress.ip_network("ff00::/8"),           # Multicast (RFC 4291)
]

# Explicit single IP blacklist for known cloud metadata
EXPLICIT_METADATA_IPS = {
    "169.254.169.254",
    "100.100.100.200",  # Alibaba cloud metadata
    "fd00:ec2::254",    # AWS IPv6 metadata
}


class SSRFValidationError(HTTPException):
    """Raised when an address or URL fails SSRF security checks."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def canonicalize_ip_representation(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """
    Attempt to parse alternative/encoded representations of IP addresses.

    Handles:
    - Standard IPv4 / IPv6 dotted / hex strings
    - Decimal dword (e.g. 2130706433 -> 127.0.0.1)
    - Octal IP representations (e.g. 0177.0.0.1 -> 127.0.0.1)
    - Hex representations (e.g. 0x7f000001 or 0x7f.0.0.1 -> 127.0.0.1)
    - Bracketed IPv6 strings (e.g. [::1])
    """
    cleaned = host.strip("[]").strip()

    # 1. Decimal integer IP representation (dword)
    if cleaned.isdigit():
        try:
            val = int(cleaned)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass

    # 2. Standard ip_address parse
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        pass

    # 3. Octal or Hex dotted IP representation (via socket.inet_aton)
    try:
        raw_bytes = socket.inet_aton(cleaned)
        # inet_aton accepts leading zeros as octal and 0x as hex
        return ipaddress.IPv4Address(raw_bytes)
    except Exception:
        pass

    return None


def is_prohibited_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address | str) -> Tuple[bool, str]:
    """
    Examine an IP address against comprehensive non-public and restricted network policies.

    Returns:
        (is_prohibited: bool, reason: str)
    """
    if isinstance(ip, str):
        parsed = canonicalize_ip_representation(ip)
        if parsed is None:
            return True, f"Invalid or unparseable IP address representation: {ip}"
        ip = parsed

    # Handle IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1 or ::ffff:10.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    ip_str = str(ip)

    # 1. Check explicit cloud metadata addresses
    if ip_str in EXPLICIT_METADATA_IPS:
        return True, f"Target IP {ip_str} is a designated cloud provider metadata endpoint."

    # 2. Check standard Python ipaddress classification properties
    if ip.is_loopback:
        return True, f"Loopback address ({ip}) is strictly prohibited."
    if ip.is_private:
        return True, f"Private internal network address (RFC 1918 / ULA: {ip}) is strictly prohibited."
    if ip.is_link_local:
        return True, f"Link-local address ({ip}) is strictly prohibited."
    if ip.is_multicast:
        return True, f"Multicast address ({ip}) is strictly prohibited."
    if ip.is_reserved:
        return True, f"Reserved address ({ip}) is strictly prohibited."
    if ip.is_unspecified:
        return True, f"Unspecified address ({ip}) is strictly prohibited."

    # 3. Global routability requirement
    if not ip.is_global:
        return True, f"Address ({ip}) is not globally routable."

    # 4. Check explicit prohibited subnet table
    for network in PROHIBITED_NETWORKS:
        if ip in network:
            return True, f"Address ({ip}) falls within prohibited network block {network}."

    return False, ""


def resolve_all_ip_addresses(hostname: str, port: int = 80) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """
    Dual-stack DNS resolution resolving ALL A and AAAA records.

    Fails closed on resolution failures.
    """
    resolved_ips: List[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        addr_info = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as e:
        raise SSRFValidationError(f"DNS resolution failed for host '{hostname}': {e.strerror}")
    except Exception as e:
        raise SSRFValidationError(f"DNS resolution error for host '{hostname}': {str(e)}")

    if not addr_info:
        raise SSRFValidationError(f"No A or AAAA records found for host '{hostname}'.")

    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip not in resolved_ips:
                resolved_ips.append(ip)
        except ValueError:
            raise SSRFValidationError(f"Resolved invalid IP address string '{ip_str}' for host '{hostname}'.")

    return resolved_ips


def validate_target_url(target_url: str, allow_internal_runtime: bool = False) -> str:
    """
    Validate target URL against comprehensive SSRF controls.

    Raises SSRFValidationError (HTTP 400) if destination violates security policy.
    Returns canonical validated URL.
    """
    if not target_url or not target_url.strip():
        raise SSRFValidationError("Target URL must not be empty.")

    target_url = target_url.strip()

    # Reject URLs containing control characters or whitespace
    if re.search(r"[\x00-\x1f\x7f\s]", target_url):
        raise SSRFValidationError("Target URL contains invalid control characters or whitespace.")

    try:
        parsed = urllib.parse.urlsplit(target_url)
    except Exception as e:
        raise SSRFValidationError(f"Malformed URL: {str(e)}")

    # 1. Allow only HTTP and HTTPS
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise SSRFValidationError(f"Unsupported scheme '{scheme}://'. Target URL must use http:// or https://.")

    # 2. Userinfo prohibited (prevent parser ambiguity/confusion)
    if parsed.username or parsed.password:
        raise SSRFValidationError("URL userinfo (user:pass@host) is prohibited in assessment targets.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("Target URL does not contain a valid hostname.")

    hostname_lower = hostname.lower().rstrip(".")

    # 3. Block known metadata hostnames explicitly
    if hostname_lower in BLOCKED_METADATA_HOSTNAMES or hostname_lower.endswith(".internal"):
        raise SSRFValidationError(f"Access to cloud metadata or internal host '{hostname}' is strictly prohibited.")

    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as e:
        raise SSRFValidationError(f"Invalid destination port: {str(e)}")

    if not (1 <= port <= 65535):
        raise SSRFValidationError(f"Invalid destination port {port}.")

    # Block sensitive internal infrastructure ports (SSH, Postgres, Redis, Docker, Kubelet)
    SENSITIVE_PORTS = {22, 2375, 2376, 2379, 5432, 6379, 10250, 10255}
    if port in SENSITIVE_PORTS and not allow_internal_runtime:
        raise SSRFValidationError(f"Destination port {port} is reserved for internal infrastructure services.")

    # 4. Check if hostname is an encoded or literal IP
    encoded_ip = canonicalize_ip_representation(hostname)
    if encoded_ip is not None:
        if allow_internal_runtime and encoded_ip.is_loopback:
            return target_url
        prohibited, reason = is_prohibited_ip(encoded_ip)
        if prohibited:
            raise SSRFValidationError(f"SSRF Blocked: {reason}")
        return target_url

    # 5. Dual-stack DNS resolution for hostnames
    resolved_ips = resolve_all_ip_addresses(hostname_lower, port)

    # 6. Verify EVERY resolved address. If ANY address is non-public, reject!
    for ip in resolved_ips:
        if allow_internal_runtime and ip.is_loopback:
            continue
        prohibited, reason = is_prohibited_ip(ip)
        if prohibited:
            raise SSRFValidationError(f"SSRF Blocked: Host '{hostname}' resolved to prohibited address ({ip}): {reason}")

    return target_url


# ---------------------------------------------------------------------------
# DNS-Rebinding Immune HTTP Transport & Client
# ---------------------------------------------------------------------------

class PinnedSSRFNetworkBackend(httpcore.SyncBackend):
    """
    Low-level socket backend that intercepts connect_tcp to prevent DNS rebinding.

    Validates the destination IP right before the TCP socket is opened,
    and connects directly to the pre-validated IP address while preserving
    the original Host header and TLS SNI hostname.
    """

    def __init__(self, allow_internal_runtime: bool = False) -> None:
        super().__init__()
        self.allow_internal_runtime = allow_internal_runtime

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        # Check literal IP or resolve hostname
        parsed_ip = canonicalize_ip_representation(host)
        if parsed_ip is not None:
            if not (self.allow_internal_runtime and parsed_ip.is_loopback):
                prohibited, reason = is_prohibited_ip(parsed_ip)
                if prohibited:
                    raise SSRFValidationError(f"TCP connection blocked to prohibited IP: {reason}")
            target_ip_str = str(parsed_ip)
        else:
            resolved = resolve_all_ip_addresses(host, port)
            for ip in resolved:
                if self.allow_internal_runtime and ip.is_loopback:
                    continue
                prohibited, reason = is_prohibited_ip(ip)
                if prohibited:
                    raise SSRFValidationError(f"TCP connection blocked: {host} resolved to prohibited IP: {reason}")
            # Pin to the first validated IP address
            target_ip_str = str(resolved[0])

        logger.debug("Connecting to pinned validated destination", host=host, pinned_ip=target_ip_str, port=port)
        # Connect directly to the validated IP to defeat any TTL-0 DNS rebinding attack
        return super().connect_tcp(
            target_ip_str,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class SafeSSRFTransport(httpx.HTTPTransport):
    """
    SSRF-protected HTTP transport using pinned socket connections.
    """

    def __init__(self, allow_internal_runtime: bool = False, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.allow_internal_runtime = allow_internal_runtime
        # Replace connection pool network backend with our pinned backend
        self._pool = httpcore.ConnectionPool(
            network_backend=PinnedSSRFNetworkBackend(allow_internal_runtime=allow_internal_runtime),
            ssl_context=self._pool._ssl_context if hasattr(self._pool, "_ssl_context") else None,
        )


class SafeSSRFClient(httpx.Client):
    """
    Hardened HTTP Client for security scanning and DAST probes.

    Features:
    - Pinned SSRF transport (immune to DNS rebinding).
    - Automatic redirects disabled by default; safe manual redirect validation.
    - Guaranteed connection (5s) and read (10s) timeouts.
    - Trust env disabled to prevent local HTTP_PROXY / HTTPS_PROXY bypasses.
    """

    def __init__(
        self,
        allow_internal_runtime: bool = False,
        timeout: float = 10.0,
        max_redirects: int = 5,
        verify: bool = True,
        **kwargs: Any,
    ) -> None:
        transport = SafeSSRFTransport(allow_internal_runtime=allow_internal_runtime, verify=verify)
        enforced_timeout = httpx.Timeout(timeout, connect=min(timeout, 5.0), read=timeout)

        super().__init__(
            transport=transport,
            timeout=enforced_timeout,
            follow_redirects=False,  # Redirects handled manually with per-hop SSRF validation
            trust_env=False,         # Ignore environment proxies that could bypass validation
            verify=verify,
            **kwargs,
        )
        self.allow_internal_runtime = allow_internal_runtime
        self.max_redirects = max_redirects

    def request(self, method: str, url: str | httpx.URL, **kwargs: Any) -> httpx.Response:
        """
        Execute request with manual, secure redirect validation on every hop.
        """
        current_url = str(url)
        # Pre-validate the destination URL
        validate_target_url(current_url, allow_internal_runtime=self.allow_internal_runtime)

        should_follow = kwargs.pop("follow_redirects", True) and (self.max_redirects > 0)
        redirect_count = 0
        while True:
            response = super().request(method, current_url, **kwargs)

            if response.is_redirect and should_follow:
                redirect_count += 1
                if redirect_count > self.max_redirects:
                    raise SSRFValidationError(f"Maximum redirect limit ({self.max_redirects}) exceeded.")

                location = response.headers.get("Location")
                if not location:
                    return response

                # Resolve relative redirects
                next_url = urllib.parse.urljoin(current_url, location)
                logger.info("Validating HTTP redirect destination", from_url=current_url, to_url=next_url)

                # STRICT SECURITY GATE: Re-validate redirect target URL before following!
                validate_target_url(next_url, allow_internal_runtime=self.allow_internal_runtime)

                current_url = next_url
                # Follow redirect with GET for 301/302/303 standard HTTP semantics
                if response.status_code in (301, 302, 303):
                    method = "GET"
                    kwargs.pop("content", None)
                    kwargs.pop("json", None)
                    kwargs.pop("data", None)
                continue

            return response
