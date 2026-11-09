# SENTINEL-X Security Policy & Hardening Guidelines

## 1. Zero-Trust Architectural Principles

SENTINEL-X operates under the principle that **every imported repository, Dockerfile, dependency manifest, build script, and user-supplied parameter is untrusted and potentially malicious**.

### Core Controls

1. **Subprocess Execution**:
   - `shell=True` is explicitly forbidden across the entire codebase.
   - All tool invocations use argument arrays (`List[str]`), preventing command injection via metacharacters.
   - Command timeouts are strictly enforced on all external processes.

2. **Secret Redaction & Masking**:
   - The in-memory `SecretRedactor` filters stdout and stderr streams before they reach logs or database storage.
   - Gitleaks matches have their middle entropy characters replaced with asterisks (`AKIA****WXYZ`).
   - GitHub OAuth access tokens and private secrets are encrypted using AES-128 Fernet symmetric encryption before being persisted to PostgreSQL.

3. **Runtime Isolation**:
   - Spawned containers drop all Linux capabilities (`cap_drop=['ALL']`).
   - Privilege escalation flags are disabled (`no-new-privileges:true`).
   - Memory limits (512MB) and CPU quotas defend against resource exhaustion.
   - Root filesystem is mounted read-only where possible.
   - Containers bind only to ephemeral local loopback addresses (`127.0.0.1:0`).

4. **SSRF Defense**:
   - User-supplied staging targets are validated against DNS and IP address classification.
   - Addresses in loopback (`127.0.0.0/8`, `::1`), link-local metadata (`169.254.0.0/16`), and private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are blocked.

5. **Tenant Isolation**:
   - All data queries verify that `Project.owner_id == current_user.id`.
   - Access to unauthorized projects or assessments returns `404 Not Found` rather than `403 Forbidden` to prevent object identifier enumeration.

---

## 2. Reporting a Security Vulnerability

If you discover a security vulnerability within SENTINEL-X:

1. **Do not create a public GitHub issue.**
2. Send a detailed report via encrypted email to: `security@sentinelx.local`
3. Include:
   - Description of the vulnerability.
   - Step-by-step reproduction instructions or proof of concept.
   - Potential security impact.
4. The SENTINEL-X team will respond within 48 hours with an assessment and remediation timeline.
