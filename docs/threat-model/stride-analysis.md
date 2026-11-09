# SENTINEL-X STRIDE Threat Model

This document analyzes threats according to the Microsoft STRIDE methodology.

| Threat Category | Potential Threat Vector | SENTINEL-X Mitigation |
|---|---|---|
| **Spoofing** | Attacker spoofs identity to view another tenant's security assessment. | Mandatory HS256 JWT access tokens verified on every request; tenant query filter `Project.owner_id == current_user.id` enforced at ORM level. |
| **Tampering** | Malicious repository injects shell metacharacters in commit message, branch name, or file path. | Execution strictly via argument arrays (`List[str]`) with `shell=False`. Subprocess streams are filtered for injection delimiters. |
| **Repudiation** | User denies approving a flawed remediation proposal or starting an intrusive scan. | Immutable `remediation_approvals` and `audit_logs` records capture user ID, timestamp, proposal ID, and approval rationale. |
| **Information Disclosure** | Secret scanner dumps cleartext API keys or passwords into database logs and reports. | Multi-layer redaction: in-memory `SecretRedactor` masks streams; `GitleaksScanner` applies `mask_secret()` before database persistence; sensitive OAuth tokens are encrypted with AES-128 Fernet. |
| **Denial of Service** | Repository contains a recursive fork bomb, endless loop, or massive binary file. | Strict subprocess timeouts (e.g. 120s for clone, 300s for static scans); Docker runtime limits memory to 512MB and caps CPU shares. |
| **Elevation of Privilege** | Untrusted application inside container attempts Docker breakout or kernel exploitation. | Container spawned with `cap_drop=['ALL']`, `no-new-privileges:true`, read-only root filesystems, and unprivileged user mappings. Host Docker socket is never mounted into runtime containers. |
| **SSRF (Lateral Movement)** | User configures staging target pointing to internal AWS metadata or database port. | `validate_target_url` resolves DNS and drops requests targeting `169.254.169.254`, `127.0.0.1`, `localhost`, or RFC 1918 private subnets. |
