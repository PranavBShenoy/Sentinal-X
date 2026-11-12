# SENTINEL-X — Runtime Host Deployment Guide

## Overview
The Runtime Host is a separate execution plane that executes Docker containers
isolated from the control plane. It communicates with the control plane over
mTLS + asymmetric job capability tokens.

## Architecture

### Control Plane
- FastAPI API service
- Celery worker for background tasks
- PostgreSQL database
- Redis for Celery broker
- Authorization Component (issues asymmetric capability tokens)

### Runtime Host (Execution Plane)
- Dedicated Linux VM or machine
- Runtime Host API service (FastAPI + Nginx mTLS proxy)
- Local Docker daemon
- SQLite job store and nonce store
- No control-plane secrets stored on this host

### Network Topology
- `sentinelx-runtime` network: isolated Runtime Host network
- `sentinelx-runtime-edge`: private mTLS terminator network
- No exposure to public internet for backend ports
- Only port 8443 (HTTPS with mTLS) is publicly accessible (loopback)

## Deployment

### Certificate Generation
- Generate CA certificate (kept on control plane only)
- Generate Runtime Host server certificate
- Generate client CA certificate (for verifying client certificates)
- Generate proxy token: `python3 -c "import secrets; token = secrets.token_urlsafe(48); print(token)" > runtime_host/certs/proxy_token && chmod 600 runtime_host/certs/proxy_token`

### Docker Compose Deployment
```bash
docker-compose -f docker-compose.yml up -d runtime_host nginx api
```

### Configuration Environment Variables
- `RUNTIME_HOST_PUBLIC_KEY_PATH`: Path to Ed25519 public verification key PEM
- `RUNTIME_HOST_CLIENT_CA_PATH`: Path to trusted client CA certificate PEM
- `RUNTIME_HOST_PROXY_TOKEN_FILE`: Path to protected proxy token file
- `RUNTIME_HOST_AUDIENCE`: Expected JWT audience (e.g., "runtime-host")
- `RUNTIME_HOST_ISSUER`: Expected JWT issuer (e.g., "sentinelx-authorization")
- `RUNTIME_HOST_PORT`: Internal Uvicorn listen port (default 8443)
- `RUNTIME_ARTIFACT_ORIGINS`: Comma-separated exact artifact server hostnames; empty rejects every artifact URL
- `RUNTIME_HOST_ADVERTISED_IP`: RFC1918 IPv4 address used for private job target URLs and Docker port binding
- `ADVERTISED_HOSTNAME`: Private DNS name returned for job targets; requires `RUNTIME_HOST_BIND_IP`
- `RUNTIME_HOST_BIND_IP`: RFC1918 IPv4 interface address used when binding a hostname-advertised target
- `ENVIRONMENT`: Deployment environment (production/prod enforce audience requirement)
- `APP_ENV`: Canonical environment variable; when set it takes precedence over `ENVIRONMENT` for production-only checks

## Security Controls

### mTLS Enforcement
- Nginx terminates TLS and verifies client certificates against configured CA
- Client certificates must include `clientAuth` extended key usage
- Certificate fingerprint validated against header from Nginx
- Proxy token prevents direct callers from impersonating the proxy

### Docker Security Policy (enforced by Runtime Host executor)
- `cap_drop: ALL` — drop all capabilities
- `no-new-privileges: true` — prevent privilege escalation
- `read-only` root filesystem
- Non-root user (UID 10001)
- Resource limits: 512 MB memory, 1.0 CPU, 100 PIDs
- No privileged containers
- No host filesystem mounts
- `--network=none` for builds, internal bridge for runs
- No exec after container start (`allow_exec: false`)
- No TTY (`tty: false`)

### Network Isolation
- Containers use `--internal` network (build) or isolated bridge (run)
- No host networking exposure
- Container names and network names generated internally
- Firewall blocks `169.254.169.254` (metadata endpoint) from container namespace
- Job ports bind only to the configured RFC1918 Runtime Host interface. Restrict
  the Runtime Host VM firewall/security group to the control-plane private
  subnet and assessment traffic; do not publish the target port range publicly.
- The Runtime Host API binds to `0.0.0.0` inside its service container so the
  private mTLS proxy can reach it. The proxy remains the only API ingress.

### Data Isolation
- Job state stored in SQLite on Runtime Host
- Nonce store for replay prevention
- Workspace data on control plane, NOT on Runtime Host
- No host filesystem mounts to containers

## Local Development (8 GB RAM, Ryzen 3)

### Minimal Setup
```bash
docker-compose -f docker-compose.yml up -d runtime_host nginx
```

### Running Tests
```bash
cd /home/pranav/Sentinal-X/runtime_host
PYTHONPATH=/home/pranav/Sentinal-X/runtime_host:$PYTHONPATH \
  python -m pytest tests/ --tb=short -q
# Expected: 137 passed in ~3 seconds
```

### Known Limitations
- Docker on same host as control plane (shared trust boundary)
- Not suitable for production without dedicated VM
- Some isolation features tested only via mocks
- Live Docker verification requires dedicated VM

## Production Checklist

### Pre-Deployment
- [ ] Ed25519 key pair generated (public on Runtime Host, private on control plane)
- [ ] Client CA certificate generated and distributed to clients
- [ ] Proxy token generated and secured (file with mode 0600)
- [ ] Firewall rules configured (only mTLS endpoint accessible)
- [ ] DNS/hostname configured for Runtime Host
- [ ] Storage paths created
- [ ] Backup strategy configured

### Post-Deployment
- [ ] Health check passes
- [ ] mTLS authentication works with valid client cert
- [ ] Invalid client cert rejected
- [ ] Job submission works with valid mutation token
- [ ] Tenant/assessment binding enforced
- [ ] Replay prevention works (nonce consumption)
- [ ] Job status polling works
- [ ] Job cancellation works
- [ ] Job cleanup after completion works

### Ongoing Maintenance
- [ ] Rotate certificates before expiration
- [ ] Rotate proxy token periodically
- [ ] Monitor job store size and cleanup orphans
- [ ] Monitor nonce store and cleanup expired entries
- [ ] Log rotation for nginx and Runtime Host
- [ ] Update dependencies and security patches

### Certificate Rotation and Revocation

Use the organization's managed CA for production issuance and revocation. The
repository's `generate_certs.sh` helper creates development certificates; it
does not maintain a revocation database and cannot issue production CRLs.
Never copy a CA private key to the Runtime Host, proxy, or control-plane
containers.

For routine leaf rotation:

1. Issue a replacement server or client certificate with the same required
   SAN and EKU values. Keep the existing trust CA during this overlap period.
2. Install the replacement certificate and private key with restrictive file
   permissions. Validate the certificate/key pair and chain before switching.
3. For server identity rotation, update the proxy's mounted server files and
   restart/reload the proxy. For client identity rotation, update the control
   plane certificate/key files and restart the API and worker processes.
4. Confirm an authenticated health check and a protected request using the new
   identity, then retire the old leaf certificate and key.
5. For CA rotation, deploy a bundle containing old and new trust anchors to
   verifiers first. Issue and switch leaf certificates, verify both sides,
   then remove the old CA only after all old leaves are retired.

For a compromised client certificate, revoke it in the authoritative CA
database, publish a fresh PEM CRL, and verify it with
`openssl crl -in <crl.pem> -noout -verify -CAfile <client-ca.pem>`. Install the
CRL at the path mounted into the proxy and set `NGINX_CLIENT_CRL` to that path.
Set `NGINX_REQUIRE_CRL=true` so startup fails if the CRL is missing. Restart
the proxy to load the new CRL; its entrypoint validates the CRL and runs
`nginx -t` before starting. Confirm the revoked client is rejected and a
non-revoked client remains accepted. Keep the CRL renewed before `nextUpdate`;
monitor its expiry and alert on failed proxy startup. Treat CRL publication or
validation failure as a deployment incident and do not disable revocation
checking to restore service.
