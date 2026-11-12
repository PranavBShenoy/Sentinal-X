# SENTINEL-X — Runtime Host Security Guide

## Threat Model

### Attacker Capabilities
- Compromised worker process on control plane
- Compromised Runtime Host VM
- Network attacker (on-control-plane network)
- Malicious container on Runtime Host
- Replay of intercepted job tokens

### Attackers Goals
- Gain host Docker socket access from control plane
- Extract Ed25519 private signing key
- Submit unauthorized jobs to Runtime Host
- Read arbitrary files from Runtime Host filesystem
- Escape container to host system
- Perform privilege escalation within container
- Replay intercepted job tokens
- Access metadata from target containers

### Trust Boundaries
- **Control plane → Runtime Host**: mTLS + capability tokens (isolated)
- **Runtime Host → Docker daemon**: Local only, no network exposure
- **Client → Runtime Host**: mTLS + capability tokens (verified)
- **Nginx → Runtime Host**: Internal network only

## Security Controls Implemented

### mTLS (Mutual TLS)
- Nginx terminates TLS at the edge
- Client certificates issued by trusted CA only
- Certificate must include `clientAuth` EKU
- Certificate validity checked (not before/after current time)
- Defense-in-depth: Runtime Host also verifies certificate chain
- Certificate fingerprint validated against header from Nginx

### Capability Restriction
- `cap_drop: ALL` — all capabilities dropped from containers
- No capability addition (`cap_add: none`)
- Containers start with minimal capability set

### Privilege Restriction
- `no-new-privileges: true` — kernel prevents `setuid`/`setgid` inside container
- Non-root user: UID 10001:GID 10001
- No `--privileged` mode
- No `--device` additions

### Filesystem Restriction
- `read-only` root filesystem
- No bind mounts from host to container
- No `--volume` flags allowing host path access
- Container generates its own names internally

### Resource Isolation
- Memory limit: 512 MB (configurable)
- CPU limit: 1.0 cores (configurable)
- PID limit: 100 (prevents fork bombs)
- No unlimited RPC calls
- Timeout limits: build 180s, runtime 3600s

### Network Restriction
- Build phase: `--network=none` (no network access)
- Run phase: internal bridge network only
- No host port mapping except explicitly published `127.0.0.1:<host_port>:<container_port>`
- No external DNS resolution from containers (controlled via `--dns`)
- Metadata endpoint `169.254.169.254` blocked by network policy

### Certificate and Key Management
- Ed25519 key pair: private key KEPT EXCLUSIVELY on control plane
- Public verification key mounted read-only to Runtime Host at `/etc/nginx/tls/public_key.pem` (note: Nginx uses server.crt/key for its own cert, public key is for token verification)
- Client CA certificate distributed to trusted clients only
- Proxy token shared secret (>=32 chars, A-Za-z0-9_- only, no placeholders)
- Certificate revocation possible via CRL (configure via `NGINX_REQUIRE_CRL`)

### Job Token Security
- Asymmetric signing: Authorization Component signs with private key
- Runtime Host verifies with public key only
- Each token has `jti` (JWT ID) for replay prevention
- Mutation tokens are one-time-use only
- Read tokens reusable within TTL but validated per-request
- Token claims verified: `tenant_id`, `assessment_id`, `job_id`, `operation`, `resources`
- Resource limits validated against token claims

### Replay Prevention
- Nonce store (SQLite on Runtime Host) tracks consumed mutation token JTIs
- One-time consumption atomic via SQLite INSERT with UNIQUE constraint
- Nonce TTL: 5 minutes (configurable via `NONCE_TTL_SECONDS`)
- Expired nonces cleaned up periodically
- `is_consumed()` check available for pre-flight validation

### Defense in Depth
- Nginx validates client certificate chain before passing to Runtime Host
- Runtime Host verifies certificate independently as second layer
- All untrusted input (especially Runtime Host responses) validated as untrusted
- Fail-closed: missing/invalid configuration prevents service startup
- No secrets in logs (structured logging, redaction)
- Constant-time token comparison to prevent timing attacks

### Certificate and Key Protection
- Private Ed25519 key NEVER mounted to Runtime Host
- Public key only (PEM format) mounted read-only
- Client CA certificate distributed to clients, kept on control plane
- Server certificate/key on Runtime Host at `/etc/nginx/tls/`
- Certificate files mode 0600 (owner read-only)
- Docker secret for proxy token (mode 0600)
- No real secrets in documentation or example files

## Security Assumptions

### Assumed Secure
- Control plane host is trusted (physical security, admin access controlled)
- Network between control plane and Runtime Host is trusted (internal network)
- Client certificates are issued by trusted CA and not compromised
- Docker daemon on Runtime Host VM is configured and running correctly
- SQLite databases are not corrupted (regular backup recommended)
- Environment variables and files with secrets have proper file permissions

### Assumptions May Not Hold (Risk Areas)
- If control plane is fully compromised, attacker could potentially:
  - Obtain proxy token from environment/configuration
  - Craft forged capability tokens (if they obtain signing key)
  - Bypass mTLS if they control the network between control plane and Runtime Host
- If Runtime Host VM is fully compromised:
  - Access to SQLite job store and nonce store
  - Access to Docker daemon for container manipulation
  - Access to filesystem outside container restrictions
  - Potential lateral movement to other hosts on same network segment

### Zero-Trust Principles Applied
- Never trust client-supplied Docker parameters (all generated internally)
- Validate all responses from Runtime Host as untrusted data
- Principle of least privilege everywhere (non-root, cap_drop ALL)
- Fail closed on any missing or invalid configuration
- Defense in depth: multiple independent security controls
- Assume network between any components may be compromised

## Security Testing

### Unit Tests
- 137 tests in `runtime_host/tests/` — all pass without Docker
- Tests cover: authentication, authorization, job state, nonce consumption, state transitions

### Integration Tests (blocked — Docker required)
- End-to-end job submission via mTLS + capability token
- Container build and run with security policy
- Job cancellation and cleanup
- Nonce replay prevention
- State transition validation

### Manual Verification Checklist
- [ ] mTLS: valid client cert accepted, invalid rejected
- [ ] Token: valid mutation token accepted, replay rejected
- [ ] Tenant: binding enforced, mismatch rejected
- [ ] Assessment: binding enforced, mismatch rejected
- [ ] Operation: build/run/cleanup/cancel only
- [ ] Resources: exact match enforced
- [ ] Network: no host exposure
- [ ] Resources: no privileged containers
- [ ] Resources: read-only filesystem
- [ ] Resources: cap_drop ALL
- [ ] Resources: no-new-privileges

## Compliance

### Related Standards
- **CIS Docker Benchmark**: Security settings aligned where possible
- **NIST SP 800-190**: Container security guidance followed
- **OWASP Container Security**: Practices applied

### Compliance Notices
- No PCI DSS requirements apply (no payment data handling)
- No HIPAA requirements apply (no health data handling)
- GDPR: No personal data processed beyond job metadata
- All data encrypted at rest (SQLite with OS-level file permissions)
- All data in transit protected by mTLS