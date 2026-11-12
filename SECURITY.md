# SENTINEL-X Security Architecture & Policy Guidelines

## 1. Zero-Trust Architectural Principles

SENTINEL-X operates under the principle that **every imported repository, Dockerfile, dependency manifest, build script, staging URL, and user-supplied parameter is untrusted and potentially malicious**.

The platform is engineered with defense-in-depth across the API control plane, execution workers, container runtimes, and external integrations.

---

## 2. Server-Side Request Forgery (SSRF) Defense & Safe HTTP Transport

All external HTTP requests—including staging target probing, DAST scans, and webhooks—are routed through the hardened SSRF protection engine located in [`backend/app/core/ssrf.py`](file:///home/pranav/Sentinal-X/backend/app/core/ssrf.py).

### 2.1 Prohibited Address & Network Matrix
The platform strictly rejects non-public, reserved, or internal infrastructure IP addresses:
- **Loopback**: `127.0.0.0/8`, `::1/128`
- **RFC 1918 Private Networks**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **IPv6 Unique Local Addresses (ULA)**: `fc00::/7` (including `fd00::/8`)
- **Link-Local Unicast**: `169.254.0.0/16`, `fe80::/10`
- **Shared Address Space / CGNAT**: `100.64.0.0/10` (RFC 6598)
- **Documentation & Benchmark Subnets**: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15`, `2001:db8::/32`
- **Cloud Metadata Endpoints**: `169.254.169.254` (AWS/GCP/Azure), `fd00:ec2::254` (AWS IPv6), `100.100.100.200` (Alibaba Cloud), `metadata.google.internal`, `metadata.aws`, `kubernetes.default.svc.cluster.local`
- **Non-Globally Routable Check**: Any IP where `not ip.is_global` is rejected.

### 2.2 Alternative IP Encoding Canonicalization
Attackers frequently use alternative numeric representations to bypass naive regex filters. SENTINEL-X canonicalizes and decodes:
- **Decimal Dword**: e.g., `http://2130706433/` -> `127.0.0.1`
- **Octal IP Formats**: e.g., `http://0177.0.0.1/` -> `127.0.0.1`
- **Hex Formats**: e.g., `http://0x7f000001/` or `http://0x7f.0.0.1/` -> `127.0.0.1`
- **IPv4-Mapped IPv6**: e.g., `::ffff:127.0.0.1` unmapped to IPv4 `127.0.0.1`

### 2.3 Dual-Stack DNS Resolution & Fail-Closed Policy
- Hostnames are resolved against both `A` (IPv4) and `AAAA` (IPv6) records.
- If **any** resolved IP address belongs to a prohibited subnet (e.g., DNS rebinding or dual-homed host), the request is rejected immediately.
- If DNS resolution fails, times out, or returns no records, the system **fails closed** and blocks the request.

### 2.4 Pinned IP Socket Transport (Anti-DNS Rebinding)
Standard HTTP client libraries re-resolve DNS between validation and connection, exposing a Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding vulnerability.
SENTINEL-X implements `PinnedSSRFNetworkBackend` on top of `httpcore.SyncBackend`. It validates the destination IP right before the raw TCP socket is created and connects directly to the pre-validated IP address, while preserving the original `Host` header and TLS Server Name Indication (SNI).

### 2.5 Redirect Safety & Strict Timeouts
- Automated redirects (`follow_redirects=True`) are disabled.
- The `SafeSSRFClient` manually intercepts 3xx redirects and re-evaluates the `Location` header through full SSRF validation before establishing a new connection.
- Strict connection (5s) and read (10s) timeouts prevent slowloris/hanging attacks.

---

## 3. Distributed Atomic Rate Limiting (OPS-01)

API abuse prevention is handled by a shared Redis-backed sliding-window rate limiter in [`backend/app/core/rate_limiter.py`](file:///home/pranav/Sentinal-X/backend/app/core/rate_limiter.py).

### 3.1 Redis Sliding Window via Atomic Lua Script
To eliminate race conditions across multiple FastAPI worker processes or load-balanced replicas:
1. `ZREMRANGEBYSCORE`: Purges expired timestamps older than the sliding window (`now - window_seconds`).
2. `ZCARD`: Counts remaining requests in the window.
3. If count < limit: `ZADD` appends the current timestamp and `EXPIRE` sets the TTL.
4. Returns remaining quota and computed retry delay atomically in a single Redis roundtrip.

### 3.2 Client IP Spoofing Prevention (`TRUSTED_PROXIES`)
Client IP resolution does **not** naively trust `X-Forwarded-For`.
- The immediate socket peer address (`request.client.host`) is checked against `TRUSTED_PROXIES` (configured via environment).
- If the peer is not an explicitly trusted reverse proxy (e.g., Cloudflare, AWS ALB, Nginx), `X-Forwarded-For` is completely ignored and the direct socket peer IP is used.
- If the peer is trusted, the rightmost untrusted IP in `X-Forwarded-For` is selected.

### 3.3 RFC 6585 Compliance
When a rate limit is exceeded:
- Responds with HTTP `429 Too Many Requests`.
- Sets standard headers: `Retry-After` (seconds until next allowed request), `X-RateLimit-Limit`, `X-RateLimit-Remaining: 0`, and `X-RateLimit-Reset` (epoch timestamp).

### 3.4 Resiliency & Degraded State Reporting
If Redis becomes unavailable, the rate limiter falls back to a fail-safe degraded mode so legitimate traffic is not hard-blocked, while reporting degraded health through `/health`.

---

## 4. Container Runtime Hardening (INFRA-01)

The Docker runtime orchestrator ([`backend/app/runtime/docker/orchestrator.py`](file:///home/pranav/Sentinal-X/backend/app/runtime/docker/orchestrator.py)) provisions ephemeral test containers under strict containment controls:

### 4.1 Linux Security Controls
- **Dropped Capabilities**: `cap_drop=['ALL']` drops all root capabilities (e.g., `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_RAW_NET`).
- **No New Privileges**: `--security-opt=no-new-privileges:true` prevents `setuid` binaries or capabilities from escalating permissions.
- **Read-Only Root Filesystem**: `--read-only` prevents any modifications to system libraries or container binaries.
- **Restricted Ephemeral Storage**: `--tmpfs=/tmp:rw,noexec,nosuid,size=64m` provides volatile, execution-blocked temporary storage.
- **Cgroups Resource Limits**:
  - Memory: 512MB hard limit (`mem_limit="512m"`).
  - CPU: 1.0 core quota (`cpu_quota=100000`, `cpu_period=100000`).
  - PIDs: Maximum 100 processes (`pids_limit=100`) to defeat fork-bombs.
- **Ephemeral Loopback Binding**: Containers bind exclusively to random unprivileged ports on `127.0.0.1:0` (`publish_all_ports=False`).

### 4.2 Non-Root User Execution
Automatically generated Dockerfiles enforce least privilege:
- Python applications: Dedicated unprivileged system user `appuser` (UID 10001, GID 10001) with `/bin/false` shell.
- Node.js applications: Official unprivileged `node` user (UID 1000).
- Root execution inside containers is strictly prohibited.

### 4.3 Enterprise MicroVM Roadmap (gVisor / Firecracker)
Standard Linux container runtimes share the host kernel. For multi-tenant production environments analyzing untrusted user code, SENTINEL-X is architecturally designed to support:
- **gVisor (`runsc`)**: User-space kernel intercepting all application syscalls, providing strong sandbox isolation.
- **AWS Firecracker**: Lightweight microVMs with dedicated guest kernels and minimal device emulation, providing hardware-level virtualization with sub-second launch times.

---

## 5. Multi-Tenant Isolation & IDOR/BOLA Defenses

Every resource across all endpoints is scoped to the authenticated tenant:
- **Project Ownership**: `Project.owner_id == current_user.id`.
- **Hierarchical Access Verification**: Repositories, assessments, findings, SBOM artifacts, reports, and remediation proposals verify ownership through relational joins back to `Project.owner_id`.
- **404 / 403 Defense**: Unauthorized access attempts return `403 Forbidden` or `404 Not Found`, preventing ID enumeration and resource discovery.
- **Test Coverage**: Verified with comprehensive multi-tenant integration tests in `backend/tests/integration/test_tenant_isolation_deep.py`.

---

## 6. Secret Redaction & Cryptographic Protections

1. **In-Memory Secret Masking**:
   - `SecretRedactor` scrubs logs, scanner outputs, and API responses.
   - Gitleaks findings mask middle entropy characters: `AKIA****WXYZ`.
2. **At-Rest Encryption**:
   - GitHub OAuth access tokens and sensitive configurations are encrypted in PostgreSQL using AES-128 Fernet symmetric encryption.
3. **Subprocess Injection Defense**:
   - `shell=True` is prohibited throughout the entire codebase. All commands are executed as explicit argument vectors (`List[str]`).

---

## 7. Reporting a Security Vulnerability

If you discover a security vulnerability within SENTINEL-X:
1. **Do not open a public GitHub issue.**
2. Send an email with reproduction details to: `security@sentinelx.local`
3. Response SLA: within 48 hours with an assessment and remediation timeline.
