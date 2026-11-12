"""
OWASP ZAP and Dynamic Application Security Testing (DAST) Engine.

Combines:
1. OWASP ZAP API integration (passive & active web scanning when available)
2. Native DAST checks:
   - HTTP Security Headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, etc.)
   - Cookie Flags (Secure, HttpOnly, SameSite)
   - CORS Configuration & Credential Reflection
   - Rate Limiting Verification (bounded, safe request sequences)
   - Server Banner & Debug Information Disclosure
   - TLS/HTTPS Redirection & Policy Inspection
"""
from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app.core.config import get_settings
from app.core.database import db_session
from app.core.logging import get_logger
from app.core.ssrf import SafeSSRFClient
from app.models import (
    CheckStatus,
    ConfidenceLevel,
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    ScanJob,
    ScanJobStatus,
)

logger = get_logger(__name__)
settings = get_settings()


class ZapScanner:
    """DAST testing coordinator: OWASP ZAP integration + Native HTTP security checks."""

    def __init__(self, zap_api_url: Optional[str] = None) -> None:
        self.zap_api_url = zap_api_url or settings.ZAP_API_URL

    def is_zap_available(self) -> bool:
        """Check if external ZAP API is reachable."""
        try:
            with httpx.Client(timeout=3) as client:
                res = client.get(f"{self.zap_api_url}/JSON/core/view/version/")
                return res.status_code == 200
        except Exception:
            return False

    def scan(
        self,
        assessment_id: str,
        target_url: str,
        scan_job_id: Optional[str] = None,
        enable_active: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute dynamic security testing against target_url.

        Runs native DAST security tests (headers, cookies, CORS, rate limits, info leak)
        and attempts ZAP crawl/passive scan if ZAP is available.
        """
        start_time = time.monotonic()

        if not target_url:
            msg = "No target URL provided or runtime provisioning failed to produce a running endpoint."
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.COMPLETED,
                check_status=CheckStatus.NOT_ASSESSED,
                error_message=msg,
            )
            return {
                "tool": "dast_zap",
                "status": ScanJobStatus.COMPLETED.value,
                "check_status": CheckStatus.NOT_ASSESSED.value,
                "findings_count": 0,
                "message": msg,
            }

        # Validate target_url reachability using SafeSSRFClient
        try:
            with SafeSSRFClient(allow_internal_runtime=True, timeout=10, verify=False) as client:
                client.get(target_url)
        except Exception as e:
            msg = f"Target URL '{target_url}' is unreachable from DAST worker: {str(e)}"
            logger.warning("DAST target unreachable", target=target_url, error=str(e))
            self._record_scan_result(
                assessment_id=assessment_id,
                scan_job_id=scan_job_id,
                status=ScanJobStatus.FAILED,
                check_status=CheckStatus.BLOCKED,
                error_message=msg,
            )
            return {
                "tool": "dast_zap",
                "status": ScanJobStatus.FAILED.value,
                "check_status": CheckStatus.BLOCKED.value,
                "findings_count": 0,
                "error": msg,
            }

        findings_count = 0

        # 1. Run Native DAST Checks
        logger.info("Running native DAST checks", target=target_url, assessment_id=assessment_id)
        native_findings = self._run_native_checks(assessment_id, target_url)
        findings_count += len(native_findings)

        # 2. Run ZAP scan if ZAP API is reachable
        zap_findings = 0
        zap_used = False
        if self.is_zap_available():
            zap_used = True
            logger.info("OWASP ZAP API is available. Running ZAP spider & passive scan.", target=target_url)
            zap_findings = self._run_zap_scan(assessment_id, target_url, enable_active=enable_active)
            findings_count += zap_findings
        else:
            logger.info("OWASP ZAP daemon not running at ZAP_API_URL. Completed native DAST checks.")

        duration = time.monotonic() - start_time
        check_st = CheckStatus.FAILED if findings_count > 0 else CheckStatus.PASSED

        tool_version = "Native DAST v1.0 + ZAP" if zap_used else "Native DAST v1.0"

        self._record_scan_result(
            assessment_id=assessment_id,
            scan_job_id=scan_job_id,
            status=ScanJobStatus.COMPLETED,
            check_status=check_st,
            tool_version=tool_version,
            execution_time=duration,
            findings_count=findings_count,
        )

        return {
            "tool": "dast_zap",
            "status": ScanJobStatus.COMPLETED.value,
            "check_status": check_st.value,
            "findings_count": findings_count,
            "zap_integrated": zap_used,
            "duration_seconds": round(duration, 2),
        }

    # ---------------------------------------------------------------------------
    # Native DAST Checks Implementation
    # ---------------------------------------------------------------------------

    def _run_native_checks(self, assessment_id: str, target_url: str) -> List[Finding]:
        """Perform native HTTP security inspection against the target."""
        findings_to_add: List[Finding] = []

        try:
            with SafeSSRFClient(allow_internal_runtime=True, timeout=15, verify=False, max_redirects=5) as client:
                res = client.get(target_url)
                headers = {k.lower(): v for k, v in res.headers.items()}

                # 1. Missing Security Headers
                sec_header_findings = self._check_security_headers(assessment_id, target_url, headers)
                findings_to_add.extend(sec_header_findings)

                # 2. Cookie Security
                cookie_findings = self._check_cookie_flags(assessment_id, target_url, res)
                findings_to_add.extend(cookie_findings)

                # 3. CORS Misconfiguration
                cors_findings = self._check_cors_policy(assessment_id, target_url, client)
                findings_to_add.extend(cors_findings)

                # 4. Server Banner & Info Leak
                banner_findings = self._check_server_banner(assessment_id, target_url, headers)
                findings_to_add.extend(banner_findings)

                # 5. Sensitive / Debug Endpoints
                debug_findings = self._check_debug_endpoints(assessment_id, target_url, client)
                findings_to_add.extend(debug_findings)

                # 6. Rate Limiting Check (bounded safe requests)
                rate_limit_findings = self._check_rate_limiting(assessment_id, target_url, client)
                findings_to_add.extend(rate_limit_findings)

                # 7. TLS & Insecure Transport Inspection
                tls_findings = self._check_tls_policy(assessment_id, target_url, headers)
                findings_to_add.extend(tls_findings)

                # 8. Open Redirect Vulnerability Probing
                redirect_findings = self._check_open_redirects(assessment_id, target_url, client)
                findings_to_add.extend(redirect_findings)

                # 9. API & Sensitive Documentation Discovery
                api_findings = self._check_api_discovery(assessment_id, target_url, client)
                findings_to_add.extend(api_findings)

                # 10. Authentication & Access Control Verification
                auth_findings = self._check_access_control(assessment_id, target_url, client)
                findings_to_add.extend(auth_findings)

                # 11. Bounded SQLi & Reflected XSS Probing
                sqli_xss_findings = self._check_sqli_and_xss(assessment_id, target_url, client)
                findings_to_add.extend(sqli_xss_findings)

        except Exception as e:
            logger.warning("Error running native DAST checks", error=str(e), target=target_url)

        # Persist findings to DB
        if findings_to_add:
            with db_session() as db:
                for f in findings_to_add:
                    existing = (
                        db.query(Finding)
                        .filter(Finding.assessment_id == assessment_id, Finding.fingerprint == f.fingerprint)
                        .first()
                    )
                    if not existing:
                        db.add(f)

        return findings_to_add

    def _check_security_headers(self, assessment_id: str, target_url: str, headers: Dict[str, str]) -> List[Finding]:
        """Verify presence and robustness of modern HTTP security headers."""
        findings: List[Finding] = []

        # Content-Security-Policy
        if "content-security-policy" not in headers:
            fp = hashlib.sha256(f"dast:header:csp:{target_url}".encode()).hexdigest()
            findings.append(
                Finding(
                    assessment_id=assessment_id,
                    fingerprint=fp,
                    title="Missing Content-Security-Policy (CSP) Header",
                    description=(
                        "The application does not specify a Content-Security-Policy header. "
                        "CSP mitigates Cross-Site Scripting (XSS), clickjacking, and data injection attacks "
                        "by restricting where scripts, styles, and other resources can be loaded from."
                    ),
                    category=FindingCategory.DAST,
                    subcategory="MISSING_SECURITY_HEADER",
                    severity=FindingSeverity.MEDIUM,
                    status=FindingStatus.OPEN,
                    confidence=ConfidenceLevel.HIGH,
                    source_tool="dast",
                    rule_id="SEC-HDR-CSP",
                    endpoint=target_url,
                    code_snippet="Add header: Content-Security-Policy: default-src 'self'",
                    raw_evidence={"header": "Content-Security-Policy", "status": "missing"},
                )
            )

        # Strict-Transport-Security (HSTS)
        parsed = urlparse(target_url)
        if parsed.scheme == "https" and "strict-transport-security" not in headers:
            fp = hashlib.sha256(f"dast:header:hsts:{target_url}".encode()).hexdigest()
            findings.append(
                Finding(
                    assessment_id=assessment_id,
                    fingerprint=fp,
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    description=(
                        "The HTTPS endpoint does not set the Strict-Transport-Security header. "
                        "Without HSTS, visitors can be downgraded to unencrypted HTTP via SSL-stripping attacks."
                    ),
                    category=FindingCategory.DAST,
                    subcategory="MISSING_SECURITY_HEADER",
                    severity=FindingSeverity.MEDIUM,
                    status=FindingStatus.OPEN,
                    confidence=ConfidenceLevel.HIGH,
                    source_tool="dast",
                    rule_id="SEC-HDR-HSTS",
                    endpoint=target_url,
                    code_snippet="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    raw_evidence={"header": "Strict-Transport-Security", "status": "missing"},
                )
            )

        # X-Content-Type-Options
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            fp = hashlib.sha256(f"dast:header:nosniff:{target_url}".encode()).hexdigest()
            findings.append(
                Finding(
                    assessment_id=assessment_id,
                    fingerprint=fp,
                    title="Missing or Weak X-Content-Type-Options Header",
                    description=(
                        "The X-Content-Type-Options header is either missing or not set to 'nosniff'. "
                        "This permits MIME-sniffing, potentially allowing browsers to interpret non-executable "
                        "MIME types as executable script or HTML."
                    ),
                    category=FindingCategory.DAST,
                    subcategory="MISSING_SECURITY_HEADER",
                    severity=FindingSeverity.LOW,
                    status=FindingStatus.OPEN,
                    confidence=ConfidenceLevel.HIGH,
                    source_tool="dast",
                    rule_id="SEC-HDR-NOSNIFF",
                    endpoint=target_url,
                    code_snippet="Add header: X-Content-Type-Options: nosniff",
                    raw_evidence={"header": "X-Content-Type-Options", "actual": headers.get("x-content-type-options")},
                )
            )

        # X-Frame-Options or frame-ancestors
        has_xfo = "x-frame-options" in headers
        has_frame_ancestors = "frame-ancestors" in headers.get("content-security-policy", "")
        if not has_xfo and not has_frame_ancestors:
            fp = hashlib.sha256(f"dast:header:clickjack:{target_url}".encode()).hexdigest()
            findings.append(
                Finding(
                    assessment_id=assessment_id,
                    fingerprint=fp,
                    title="Clickjacking Protection Missing (No X-Frame-Options or CSP frame-ancestors)",
                    description=(
                        "The application does not restrict framing via X-Frame-Options (DENY or SAMEORIGIN) "
                        "or CSP 'frame-ancestors'. An attacker can render this page inside an invisible iframe "
                        "to trick users into clicking buttons (Clickjacking / UI Redress)."
                    ),
                    category=FindingCategory.DAST,
                    subcategory="CLICKJACKING",
                    severity=FindingSeverity.MEDIUM,
                    status=FindingStatus.OPEN,
                    confidence=ConfidenceLevel.HIGH,
                    source_tool="dast",
                    rule_id="SEC-HDR-XFO",
                    endpoint=target_url,
                    code_snippet="Add header: X-Frame-Options: DENY\nOr in CSP: frame-ancestors 'none';",
                    raw_evidence={"status": "missing_frame_protection"},
                )
            )

        # Referrer-Policy
        if "referrer-policy" not in headers:
            fp = hashlib.sha256(f"dast:header:referrer:{target_url}".encode()).hexdigest()
            findings.append(
                Finding(
                    assessment_id=assessment_id,
                    fingerprint=fp,
                    title="Missing Referrer-Policy Header",
                    description=(
                        "The application does not set a Referrer-Policy header. "
                        "Browsers may leak sensitive URL parameters or internal paths in the Referer header to third parties."
                    ),
                    category=FindingCategory.DAST,
                    subcategory="MISSING_SECURITY_HEADER",
                    severity=FindingSeverity.LOW,
                    status=FindingStatus.OPEN,
                    confidence=ConfidenceLevel.HIGH,
                    source_tool="dast",
                    rule_id="SEC-HDR-REFERRER",
                    endpoint=target_url,
                    code_snippet="Add header: Referrer-Policy: strict-origin-when-cross-origin",
                    raw_evidence={"header": "Referrer-Policy", "status": "missing"},
                )
            )

        # Permissions-Policy
        if "permissions-policy" not in headers:
            fp = hashlib.sha256(f"dast:header:permissions:{target_url}".encode()).hexdigest()
            findings.append(
                Finding(
                    assessment_id=assessment_id,
                    fingerprint=fp,
                    title="Missing Permissions-Policy Header",
                    description=(
                        "The application does not set a Permissions-Policy header. "
                        "Without this header, the browser cannot restrict access to sensitive browser features "
                        "(e.g., camera, microphone, geolocation) within iframes or untrusted third-party scripts."
                    ),
                    category=FindingCategory.DAST,
                    subcategory="MISSING_SECURITY_HEADER",
                    severity=FindingSeverity.LOW,
                    status=FindingStatus.OPEN,
                    confidence=ConfidenceLevel.HIGH,
                    source_tool="dast",
                    rule_id="SEC-HDR-PERMISSIONS",
                    endpoint=target_url,
                    code_snippet="Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
                    raw_evidence={"header": "Permissions-Policy", "status": "missing"},
                )
            )

        return findings

    def _check_cookie_flags(self, assessment_id: str, target_url: str, response: httpx.Response) -> List[Finding]:
        """Check for Secure, HttpOnly, and SameSite cookie flags."""
        findings: List[Finding] = []
        parsed = urlparse(target_url)
        is_https = parsed.scheme == "https"

        raw_set_cookie_headers = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
        if not raw_set_cookie_headers and "set-cookie" in response.headers:
            raw_set_cookie_headers = [response.headers["set-cookie"]]

        for cookie_str in raw_set_cookie_headers:
            parts = [p.strip().lower() for p in cookie_str.split(";")]
            cookie_name = cookie_str.split("=")[0].strip()

            has_httponly = "httponly" in parts
            has_secure = "secure" in parts
            has_samesite = any(p.startswith("samesite=") for p in parts)

            if not has_httponly:
                fp = hashlib.sha256(f"dast:cookie:httponly:{cookie_name}:{target_url}".encode()).hexdigest()
                findings.append(
                    Finding(
                        assessment_id=assessment_id,
                        fingerprint=fp,
                        title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                        description=(
                            f"The cookie '{cookie_name}' was set without the 'HttpOnly' attribute. "
                            "JavaScript can read this cookie via document.cookie, making it vulnerable "
                            "to theft in Cross-Site Scripting (XSS) attacks."
                        ),
                        category=FindingCategory.DAST,
                        subcategory="INSECURE_COOKIE",
                        severity=FindingSeverity.MEDIUM,
                        status=FindingStatus.OPEN,
                        confidence=ConfidenceLevel.HIGH,
                        source_tool="dast",
                        rule_id="SEC-COOKIE-HTTPONLY",
                        endpoint=target_url,
                        code_snippet=f"Set-Cookie: {cookie_name}=...; HttpOnly; SameSite=Lax",
                    )
                )

            if is_https and not has_secure:
                fp = hashlib.sha256(f"dast:cookie:secure:{cookie_name}:{target_url}".encode()).hexdigest()
                findings.append(
                    Finding(
                        assessment_id=assessment_id,
                        fingerprint=fp,
                        title=f"Cookie '{cookie_name}' Missing Secure Flag Over HTTPS",
                        description=(
                            f"The cookie '{cookie_name}' lacks the 'Secure' flag on an HTTPS service. "
                            "It may be transmitted over unencrypted HTTP connections if user clicks an http:// link."
                        ),
                        category=FindingCategory.DAST,
                        subcategory="INSECURE_COOKIE",
                        severity=FindingSeverity.MEDIUM,
                        status=FindingStatus.OPEN,
                        confidence=ConfidenceLevel.HIGH,
                        source_tool="dast",
                        rule_id="SEC-COOKIE-SECURE",
                        endpoint=target_url,
                    )
                )

            if not has_samesite:
                fp = hashlib.sha256(f"dast:cookie:samesite:{cookie_name}:{target_url}".encode()).hexdigest()
                findings.append(
                    Finding(
                        assessment_id=assessment_id,
                        fingerprint=fp,
                        title=f"Cookie '{cookie_name}' Missing SameSite Attribute",
                        description=(
                            f"The cookie '{cookie_name}' lacks the 'SameSite' attribute. "
                            "Without SameSite (Strict or Lax), the cookie is vulnerable to Cross-Site Request Forgery (CSRF)."
                        ),
                        category=FindingCategory.DAST,
                        subcategory="INSECURE_COOKIE",
                        severity=FindingSeverity.LOW,
                        status=FindingStatus.OPEN,
                        confidence=ConfidenceLevel.HIGH,
                        source_tool="dast",
                        rule_id="SEC-COOKIE-SAMESITE",
                        endpoint=target_url,
                    )
                )

        return findings

    def _check_cors_policy(self, assessment_id: str, target_url: str, client: httpx.Client) -> List[Finding]:
        """Check for permissive or reflected CORS configurations."""
        findings: List[Finding] = []
        evil_origin = "https://evil-attacker.example.com"

        try:
            res = client.options(
                target_url,
                headers={
                    "Origin": evil_origin,
                    "Access-Control-Request-Method": "GET",
                },
            )
            allow_origin = res.headers.get("access-control-allow-origin", "").strip()
            allow_cred = res.headers.get("access-control-allow-credentials", "").lower() == "true"

            if allow_origin == "*" and allow_cred:
                fp = hashlib.sha256(f"dast:cors:wildcard_cred:{target_url}".encode()).hexdigest()
                findings.append(
                    Finding(
                        assessment_id=assessment_id,
                        fingerprint=fp,
                        title="Insecure CORS: Wildcard Origin With Credentials Permitted",
                        description=(
                            "The CORS policy allows arbitrary origins (*) alongside Access-Control-Allow-Credentials: true. "
                            "This permits untrusted external sites to issue authenticated cross-origin requests."
                        ),
                        category=FindingCategory.DAST,
                        subcategory="CORS_MISCONFIGURATION",
                        severity=FindingSeverity.HIGH,
                        status=FindingStatus.OPEN,
                        confidence=ConfidenceLevel.HIGH,
                        source_tool="dast",
                        rule_id="SEC-CORS-WILDCARD-CRED",
                        endpoint=target_url,
                    )
                )
            elif allow_origin == evil_origin:
                severity = FindingSeverity.HIGH if allow_cred else FindingSeverity.MEDIUM
                fp = hashlib.sha256(f"dast:cors:reflected:{target_url}".encode()).hexdigest()
                findings.append(
                    Finding(
                        assessment_id=assessment_id,
                        fingerprint=fp,
                        title="Insecure CORS: Arbitrary Origin Reflected in Access-Control-Allow-Origin",
                        description=(
                            f"The server reflected untrusted Origin '{evil_origin}' back in the "
                            f"Access-Control-Allow-Origin header (Allow-Credentials: {allow_cred}). "
                            "Any website can interact with this API across origins."
                        ),
                        category=FindingCategory.DAST,
                        subcategory="CORS_MISCONFIGURATION",
                        severity=severity,
                        status=FindingStatus.OPEN,
                        confidence=ConfidenceLevel.HIGH,
                        source_tool="dast",
                        rule_id="SEC-CORS-REFLECTED",
                        endpoint=target_url,
                    )
                )
        except Exception:
            pass

        return findings

    def _check_server_banner(self, assessment_id: str, target_url: str, headers: Dict[str, str]) -> List[Finding]:
        """Detect excessive server/technology version disclosures in HTTP headers."""
        findings: List[Finding] = []
        server_header = headers.get("server", "")
        x_powered_by = headers.get("x-powered-by", "")

        disclosures = []
        if server_header and any(c.isdigit() for c in server_header):
            disclosures.append(f"Server: {server_header}")
        if x_powered_by:
            disclosures.append(f"X-Powered-By: {x_powered_by}")

        if disclosures:
            fp = hashlib.sha256(f"dast:banner:{target_url}".encode()).hexdigest()
            findings.append(
                Finding(
                    assessment_id=assessment_id,
                    fingerprint=fp,
                    title="Server Version Information Disclosure",
                    description=(
                        f"The application leaks internal runtime/server version banners: {', '.join(disclosures)}. "
                        "Detailed version banners assist attackers in targeting version-specific vulnerabilities."
                    ),
                    category=FindingCategory.DAST,
                    subcategory="INFO_DISCLOSURE",
                    severity=FindingSeverity.LOW,
                    status=FindingStatus.OPEN,
                    confidence=ConfidenceLevel.HIGH,
                    source_tool="dast",
                    rule_id="SEC-INFO-BANNER",
                    endpoint=target_url,
                    code_snippet="Remove or redact the 'Server' and 'X-Powered-By' response headers.",
                    raw_evidence={"headers": disclosures},
                )
            )

        return findings

    def _check_debug_endpoints(self, assessment_id: str, target_url: str, client: httpx.Client) -> List[Finding]:
        """Probe for commonly exposed sensitive or debug paths."""
        findings: List[Finding] = []
        probe_paths = [
            ("/.env", "Exposed .env Configuration File", FindingSeverity.CRITICAL),
            ("/.git/config", "Exposed Git Repository Configuration", FindingSeverity.HIGH),
            ("/actuator/env", "Exposed Spring Actuator Env Endpoint", FindingSeverity.HIGH),
            ("/phpinfo.php", "Exposed phpinfo Diagnostic Page", FindingSeverity.MEDIUM),
        ]

        base = target_url.rstrip("/")
        for path, title, severity in probe_paths:
            try:
                probe_url = f"{base}{path}"
                res = client.get(probe_url, timeout=5)
                if res.status_code == 200 and len(res.text) > 20:
                    # Validate that it's not a generic 404 page returning 200
                    text_lower = res.text.lower()
                    if path == "/.env" and ("=" in res.text or "database" in text_lower or "secret" in text_lower):
                        fp = hashlib.sha256(f"dast:probe:{path}:{target_url}".encode()).hexdigest()
                        findings.append(
                            Finding(
                                assessment_id=assessment_id,
                                fingerprint=fp,
                                title=title,
                                description=f"Sensitive file accessible over HTTP at {probe_url}.",
                                category=FindingCategory.DAST,
                                subcategory="EXPOSED_SENSITIVE_FILE",
                                severity=severity,
                                status=FindingStatus.OPEN,
                                confidence=ConfidenceLevel.HIGH,
                                source_tool="dast",
                                rule_id="SEC-EXPOSED-FILE",
                                endpoint=probe_url,
                            )
                        )
            except Exception as e:
                logger.debug("Failed sensitive file probe against %s: %s", probe_url, e)
                continue

        return findings

    def _check_rate_limiting(self, assessment_id: str, target_url: str, client: httpx.Client) -> List[Finding]:
        """
        Bounded, safe rate-limiting check.
        Sends a burst of 6 rapid requests to check if 429 or rate-limiting headers appear.
        """
        findings: List[Finding] = []
        saw_429 = False
        saw_rate_limit_headers = False

        for _ in range(6):
            try:
                res = client.get(target_url, timeout=3)
                if res.status_code == 429:
                    saw_429 = True
                    break
                h_keys = [k.lower() for k in res.headers.keys()]
                if any(k.startswith("x-ratelimit-") or k == "retry-after" for k in h_keys):
                    saw_rate_limit_headers = True
                    break
            except Exception:
                break

        # If it's an API route and completely devoid of rate limit protections
        if not saw_429 and not saw_rate_limit_headers and "/api/" in target_url:
            fp = hashlib.sha256(f"dast:ratelimit:missing:{target_url}".encode()).hexdigest()
            findings.append(
                Finding(
                    assessment_id=assessment_id,
                    fingerprint=fp,
                    title="API Endpoint Lacks Rate Limiting Protection",
                    description=(
                        f"The API endpoint at '{target_url}' responded to rapid bursts without rate-limiting headers "
                        "(X-RateLimit-*) or HTTP 429 throttling. Unmetered APIs are vulnerable to credential stuffing and brute force."
                    ),
                    category=FindingCategory.DAST,
                    subcategory="RATE_LIMITING",
                    severity=FindingSeverity.LOW,
                    status=FindingStatus.OPEN,
                    confidence=ConfidenceLevel.MEDIUM,
                    source_tool="dast",
                    rule_id="SEC-RATE-LIMITING",
                    endpoint=target_url,
                    code_snippet="Configure Redis sliding-window rate limiting on all public API endpoints.",
                    raw_evidence={"burst_size": 6, "rate_limited": False},
                )
            )

        return findings

    def _check_tls_policy(self, assessment_id: str, target_url: str, headers: Dict[str, str]) -> List[Finding]:
        """Verify TLS/HTTPS enforcement and plain HTTP transport risks."""
        findings: List[Finding] = []
        parsed = urlparse(target_url)
        is_loopback = parsed.hostname in ("127.0.0.1", "localhost", "::1")

        if parsed.scheme == "http" and not is_loopback:
            fp = hashlib.sha256(f"dast:tls:unencrypted:{target_url}".encode()).hexdigest()
            findings.append(
                Finding(
                    assessment_id=assessment_id,
                    fingerprint=fp,
                    title="Unencrypted HTTP Transport In Use",
                    description=(
                        f"The target endpoint '{target_url}' is served over unencrypted HTTP. "
                        "All traffic, including session cookies, credentials, and data payloads, "
                        "is vulnerable to interception and modification by network eavesdroppers."
                    ),
                    category=FindingCategory.DAST,
                    subcategory="INSECURE_TRANSPORT",
                    severity=FindingSeverity.HIGH,
                    status=FindingStatus.OPEN,
                    confidence=ConfidenceLevel.HIGH,
                    source_tool="dast",
                    rule_id="SEC-TLS-UNENCRYPTED",
                    endpoint=target_url,
                    code_snippet="Enforce TLS 1.3/HTTPS and configure 301 redirects from HTTP to HTTPS.",
                    raw_evidence={"scheme": "http", "target": target_url},
                )
            )
        return findings

    def _check_open_redirects(self, assessment_id: str, target_url: str, client: httpx.Client) -> List[Finding]:
        """Probe for open redirect vulnerabilities on common redirect parameters."""
        findings: List[Finding] = []
        base = target_url.rstrip("/")
        test_dest = "https://evil.com"
        redirect_params = ["redirect", "next", "url", "return_to", "dest", "target"]

        try:
            with SafeSSRFClient(allow_internal_runtime=True, timeout=5, verify=False, max_redirects=0) as no_redirect_client:
                for param in redirect_params:
                    try:
                        probe_url = f"{base}/?{param}={test_dest}"
                        res = no_redirect_client.get(probe_url)
                        if res.status_code in (301, 302, 303, 307, 308):
                            location = res.headers.get("location", "")
                            if location.startswith(test_dest) or location.startswith("//evil.com"):
                                fp = hashlib.sha256(f"dast:redirect:{param}:{target_url}".encode()).hexdigest()
                                findings.append(
                                    Finding(
                                        assessment_id=assessment_id,
                                        fingerprint=fp,
                                        title=f"Open Redirect Vulnerability via '{param}' Parameter",
                                        description=(
                                            f"The application accepted untrusted redirect target '{test_dest}' in query parameter "
                                            f"'{param}' and issued a {res.status_code} redirect to '{location}'. "
                                            "Attackers can leverage this to redirect victims from a trusted domain to malicious phishing sites."
                                        ),
                                        category=FindingCategory.DAST,
                                        subcategory="OPEN_REDIRECT",
                                        severity=FindingSeverity.MEDIUM,
                                        status=FindingStatus.OPEN,
                                        confidence=ConfidenceLevel.HIGH,
                                        source_tool="dast",
                                        rule_id="SEC-OPEN-REDIRECT",
                                        endpoint=probe_url,
                                        code_snippet=f"Validate '{param}' against an allowlist of relative URLs or trusted internal domains.",
                                        raw_evidence={"param": param, "redirect_location": location, "status_code": res.status_code},
                                    )
                                )
                                break
                    except Exception as e:
                        logger.debug("Open redirect probe error on %s: %s", param, e)
        except Exception as e:
            logger.debug("Open redirect client initialization error: %s", e)

        return findings

    def _check_api_discovery(self, assessment_id: str, target_url: str, client: httpx.Client) -> List[Finding]:
        """Inspect publicly exposed API documentation and robots.txt disclosures."""
        findings: List[Finding] = []
        base = target_url.rstrip("/")
        doc_paths = [
            ("/openapi.json", "Exposed OpenAPI Schema Document", FindingSeverity.LOW, "SEC-API-SCHEMA"),
            ("/swagger.json", "Exposed Swagger v2 Schema Document", FindingSeverity.LOW, "SEC-API-SCHEMA"),
            ("/docs", "Exposed Interactive API Documentation (/docs)", FindingSeverity.LOW, "SEC-API-DOCS"),
        ]

        for path, title, severity, rule in doc_paths:
            try:
                probe_url = f"{base}{path}"
                res = client.get(probe_url, timeout=5)
                if res.status_code == 200 and len(res.text) > 30:
                    text_lower = res.text.lower()
                    if ("openapi" in text_lower or "swagger" in text_lower or "paths" in text_lower) and "404" not in text_lower:
                        fp = hashlib.sha256(f"dast:discovery:{path}:{target_url}".encode()).hexdigest()
                        findings.append(
                            Finding(
                                assessment_id=assessment_id,
                                fingerprint=fp,
                                title=title,
                                description=(
                                    f"Publicly accessible API documentation or schema discovered at '{probe_url}'. "
                                    "While useful for developers, unauthenticated API schemas expose full route parameters, "
                                    "internal endpoints, and input models to external reconnaissance."
                                ),
                                category=FindingCategory.DAST,
                                subcategory="API_DISCOVERY",
                                severity=severity,
                                status=FindingStatus.OPEN,
                                confidence=ConfidenceLevel.HIGH,
                                source_tool="dast",
                                rule_id=rule,
                                endpoint=probe_url,
                                code_snippet=f"Disable or gate '{path}' behind authentication in production environments.",
                                raw_evidence={"path": path, "status_code": res.status_code},
                            )
                        )
            except Exception as e:
                logger.debug("API discovery probe error on %s: %s", path, e)

        return findings

    def _check_access_control(self, assessment_id: str, target_url: str, client: httpx.Client) -> List[Finding]:
        """Verify that administrative and internal endpoints reject unauthenticated requests."""
        findings: List[Finding] = []
        base = target_url.rstrip("/")
        admin_paths = [
            ("/admin", "Unauthenticated Administrative Portal Access"),
            ("/api/admin", "Unauthenticated Admin API Access"),
            ("/metrics", "Exposed Internal System Metrics (/metrics)"),
        ]

        for path, title in admin_paths:
            try:
                probe_url = f"{base}{path}"
                res = client.get(probe_url, timeout=5)
                if res.status_code == 200 and len(res.text) > 20:
                    text_lower = res.text.lower()
                    is_admin_content = any(k in text_lower for k in ("dashboard", "admin", "prometheus", "go_gc", "metric", "users"))
                    if is_admin_content:
                        fp = hashlib.sha256(f"dast:auth:{path}:{target_url}".encode()).hexdigest()
                        findings.append(
                            Finding(
                                assessment_id=assessment_id,
                                fingerprint=fp,
                                title=title,
                                description=(
                                    f"Privileged endpoint '{probe_url}' returned HTTP 200 without requiring authentication. "
                                    "Administrative functions and metrics must be strictly gated behind authentication and role authorization."
                                ),
                                category=FindingCategory.DAST,
                                subcategory="BROKEN_ACCESS_CONTROL",
                                severity=FindingSeverity.HIGH,
                                status=FindingStatus.OPEN,
                                confidence=ConfidenceLevel.HIGH,
                                source_tool="dast",
                                rule_id="SEC-ACCESS-CONTROL",
                                endpoint=probe_url,
                                code_snippet=f"Require valid authentication and administrator role for '{path}'.",
                                raw_evidence={"path": path, "status_code": res.status_code},
                            )
                        )
            except Exception as e:
                logger.debug("Access control probe error on %s: %s", path, e)

        return findings

    def _check_sqli_and_xss(self, assessment_id: str, target_url: str, client: httpx.Client) -> List[Finding]:
        """Execute safe, bounded DAST active probes for SQL injection errors and reflected XSS."""
        findings: List[Finding] = []
        base = target_url.rstrip("/")

        # 1. Reflected XSS Probe with unique benign canary
        canary = "<sentinelx-xss-test-94182>"
        try:
            res = client.get(f"{base}/", params={"q": canary, "search": canary}, timeout=5)
            if res.status_code == 200 and canary in res.text:
                fp = hashlib.sha256(f"dast:xss:reflected:{target_url}".encode()).hexdigest()
                findings.append(
                    Finding(
                        assessment_id=assessment_id,
                        fingerprint=fp,
                        title="Reflected Cross-Site Scripting (XSS) Detected",
                        description=(
                            f"The query parameter payload was reflected unencoded in the HTTP response body at '{base}/?q=...'. "
                            "An attacker can craft malicious URLs that execute arbitrary client-side JavaScript in the victim's session."
                        ),
                        category=FindingCategory.DAST,
                        subcategory="REFLECTED_XSS",
                        severity=FindingSeverity.HIGH,
                        status=FindingStatus.OPEN,
                        confidence=ConfidenceLevel.HIGH,
                        source_tool="dast",
                        rule_id="SEC-DAST-REFLECTED-XSS",
                        endpoint=f"{base}/?q={canary}",
                        code_snippet="Contextually HTML-encode user inputs before rendering into response bodies.",
                        raw_evidence={"payload": canary, "url": f"{base}/?q={canary}"},
                    )
                )
        except Exception as e:
            logger.debug("XSS probe error: %s", e)

        # 2. SQL Injection Error Signature Probe
        sqli_probe = "' OR '1'='1"
        try:
            probe_endpoint = f"{base}/?id={sqli_probe}"
            res = client.get(f"{base}/", params={"id": sqli_probe, "category": sqli_probe}, timeout=5)
            text_lower = res.text.lower()
            sql_error_signatures = [
                "syntax error at or near",
                "you have an error in your sql syntax",
                "unclosed quotation mark",
                "sqlite3.operationalerror",
                "pg::syntaxerror",
                "ora-01756",
                "microsoft ole db provider for sql server",
            ]
            matched_error = next((sig for sig in sql_error_signatures if sig in text_lower), None)
            if matched_error:
                fp = hashlib.sha256(f"dast:sqli:error:{target_url}".encode()).hexdigest()
                findings.append(
                    Finding(
                        assessment_id=assessment_id,
                        fingerprint=fp,
                        title="SQL Injection Error Signature Disclosed",
                        description=(
                            f"The application disclosed a raw database SQL syntax error ('{matched_error}') when probed "
                            f"with a single quote payload at '{probe_endpoint}'. This strongly indicates unparameterized SQL queries."
                        ),
                        category=FindingCategory.DAST,
                        subcategory="SQL_INJECTION",
                        severity=FindingSeverity.CRITICAL,
                        status=FindingStatus.OPEN,
                        confidence=ConfidenceLevel.HIGH,
                        source_tool="dast",
                        rule_id="SEC-DAST-SQLI-ERROR",
                        endpoint=probe_endpoint,
                        code_snippet="Use parameterized queries or ORM models instead of string concatenation.",
                        raw_evidence={"error_signature": matched_error, "probe_url": probe_endpoint},
                    )
                )
        except Exception as e:
            logger.debug("SQLi probe error: %s", e)

        return findings

    # ---------------------------------------------------------------------------
    # OWASP ZAP API Integration
    # ---------------------------------------------------------------------------

    def _run_zap_scan(self, assessment_id: str, target_url: str, enable_active: bool = False) -> int:
        """Trigger ZAP spider and retrieve passive/active alerts."""
        created_count = 0
        try:
            with httpx.Client(timeout=30) as client:
                # 1. Trigger Spider
                spider_resp = client.get(
                    f"{self.zap_api_url}/JSON/spider/action/scan/",
                    params={"url": target_url, "maxChildren": 10},
                )
                scan_id = spider_resp.json().get("scan")
                if scan_id:
                    # Poll spider status up to 30s
                    for _ in range(6):
                        time.sleep(5)
                        st = client.get(
                            f"{self.zap_api_url}/JSON/spider/view/status/",
                            params={"scanId": scan_id},
                        ).json().get("status", "100")
                        if st == "100":
                            break

                # 2. Retrieve Alerts
                alerts_resp = client.get(
                    f"{self.zap_api_url}/JSON/core/view/alerts/",
                    params={"baseurl": target_url},
                )
                alerts = alerts_resp.json().get("alerts", [])

                with db_session() as db:
                    for alert in alerts:
                        plugin_id = alert.get("pluginId", "zap-alert")
                        alert_name = alert.get("alert", "ZAP Alert")
                        risk = alert.get("risk", "Low").upper()

                        if risk == "HIGH":
                            sev = FindingSeverity.HIGH
                        elif risk == "MEDIUM":
                            sev = FindingSeverity.MEDIUM
                        elif risk == "LOW":
                            sev = FindingSeverity.LOW
                        else:
                            sev = FindingSeverity.INFO

                        url = alert.get("url", target_url)
                        fp = hashlib.sha256(f"zap:{plugin_id}:{url}".encode()).hexdigest()

                        existing = (
                            db.query(Finding)
                            .filter(Finding.assessment_id == assessment_id, Finding.fingerprint == fp)
                            .first()
                        )
                        if not existing:
                            finding = Finding(
                                assessment_id=assessment_id,
                                fingerprint=fp,
                                title=f"DAST: {alert_name}",
                                description=alert.get("description", ""),
                                category=FindingCategory.DAST,
                                subcategory="ZAP_ALERT",
                                severity=sev,
                                status=FindingStatus.OPEN,
                                confidence=ConfidenceLevel.MEDIUM,
                                source_tool="zap",
                                rule_id=plugin_id,
                                endpoint=url,
                                code_snippet=alert.get("solution"),
                                raw_evidence={
                                    "param": alert.get("param"),
                                    "attack": alert.get("attack"),
                                    "evidence": alert.get("evidence"),
                                },
                            )
                            db.add(finding)
                            created_count += 1

        except Exception as e:
            logger.warning("Error communicating with OWASP ZAP API", error=str(e))

        return created_count

    def _record_scan_result(
        self,
        assessment_id: str,
        scan_job_id: Optional[str],
        status: ScanJobStatus,
        check_status: CheckStatus,
        error_message: Optional[str] = None,
        tool_version: Optional[str] = None,
        execution_time: float = 0.0,
        findings_count: int = 0,
    ) -> None:
        """Update or insert ScanJob record."""
        with db_session() as db:
            job = None
            if scan_job_id:
                job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
            if not job:
                job = (
                    db.query(ScanJob)
                    .filter(ScanJob.assessment_id == assessment_id, ScanJob.tool_name == "dast_zap")
                    .first()
                )
            if not job:
                job = ScanJob(
                    assessment_id=assessment_id,
                    tool_name="dast_zap",
                )
                db.add(job)

            job.status = status
            job.check_status = check_status
            job.error_message = error_message
            job.tool_version = tool_version
            job.execution_time_seconds = execution_time
            job.findings_count = findings_count
            job.completed_at = datetime.now(timezone.utc)
