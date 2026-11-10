# SENTINEL-X — Docker Privilege Boundary & Runtime Isolation Architecture Review

**Status:** Deliverable only. No code changes made. Awaiting approval before implementation.
**Branch:** `fix/security-hardening-audit` (commit `be08ad3`, not pushed)
**Threat model:** Untrusted repository code is built and executed for dynamic analysis; the worker must never gain unrestricted control of the host Docker daemon.

---

## 1. Current Runtime Architecture & Execution Flow

### 1.1 Components that need Docker API access

Docker is used by **exactly one code path**: `RuntimeOrchestrator` in
`backend/app/runtime/docker/orchestrator.py`, invoked from:

- `backend/app/workers/assessment_tasks.py` — `provision_runtime` Celery task (runs in the **worker** container).
- `backend/app/services/assessment_pipeline.py` — `runtime_orch.cleanup()` in the `finally` block (runs in the **worker** container during the pipeline).
- `backend/app/api/v1/endpoints/assessments.py` — `RuntimeOrchestrator().cleanup()` called on assessment cancellation (runs in the **API** container, which does **not** mount the socket, so this path degrades gracefully / fails).

No other component (API, frontend, scanners, repository service) calls the Docker API.

### 1.2 Exact Docker CLI invocations (orchestrator shells out via `run_command`)

| # | Command | Purpose |
|---|---------|---------|
| 1 | `docker info` | Daemon availability check |
| 2 | `docker build -t <tag> <workspace>` | Build target app image (was `--network=host`, removed in commit `be08ad3`) |
| 3 | `docker rm -f <container>` | Stale-container removal before start; real cleanup |
| 4 | `docker network rm <net>` | Stale-network removal before create; real cleanup |
| 5 | `docker network create --internal <net>` | Dedicated isolated network per assessment |
| 6 | `docker run -d ... -p=127.0.0.1:<host>:<app> ... <image>` | Start hardened target container |
| 7 | `docker logs --tail=100 <container>` | Capture logs with redaction |
| 8 | `docker rm -f <container>` | Teardown (container first) |
| 9 | `docker network rm <net>` | Teardown (network second) |
| 10 | `docker rmi <image>` | Teardown (image last) |

Required Docker API surface (minimum): `images/build`, `networks/create`, `containers/create`, `containers/start`, `containers/logs`, `containers/stop`/`delete`, `networks/delete`, `images/delete`.

**Not required:** `containers/exec`, arbitrary volume/bind mounts, `docker commit`, `docker push/pull` from arbitrary registries beyond base images, `docker run --privileged`, host-path mounts, port publishing to `0.0.0.0`.

### 1.3 Execution flow (one assessment)

1. Celery worker dequeues `provision_runtime(assessment_id, workspace_path)`.
2. `RuntimeOrchestrator.provision()` → `docker build` → `docker network create --internal` → `docker run` (hardened) → health check → return `target_url` (`127.0.0.1:<host_port>`).
3. Pipeline runs DAST (ZAP/native) against `target_url`.
4. `finally:` block → `orchestrator.cleanup()` → `docker rm`, `docker network rm`, `docker rmi`.
5. API `/assessments/{id}/cancel` → `orchestrator.cleanup()` (runs in API container; socket absent → graceful no-op).

### 1.4 Current privilege boundary (the problem)

`docker-compose.yml` worker service:
```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

`infrastructure/docker/Dockerfile.worker`:
- No `USER` directive → container runs as **root**.
- Installs `docker.io` CLI; no socket proxy.

**Consequence:** The worker process runs as **root** inside a container that has an unmediated, read-only mount of the host Docker socket. Any compromise of the worker (via malicious repository code, scanner input, or a vulnerability in Celery/task handling) yields immediate, unrestricted control over `dockerd` on the host:
- `docker run -v /:/host --privileged` → read/write any host file, container escape.
- `docker exec` into any other container (including postgres/redis with credentials).
- `docker stop/rm` → denial of service of platform services.
- Image/network/volume manipulation → full host Docker control.

Target-container hardening (`cap_drop=ALL`, `no-new-privileges`, read-only rootfs, `--internal`, non-root user) protects the **target** container from the host, but does nothing to protect the host from a compromised **worker**, because the worker talks directly to `dockerd`.

> This is the single largest remaining production blocker. It is documented but **not resolved**.

---

## 2. Security Consequences of the Current Docker Socket Mount

| Risk | Explanation | Mitigated by current target-container hardening? |
|------|-------------|--------------------------------------------------|
| Container escape / host compromise | Root worker + docker.sock → full `dockerd` control | **No** — hardening applies to targets, not the worker |
| Credential theft from sibling containers | `docker exec` into postgres/redis; read env/secrets | **No** |
| Denial of service | Stop/rm platform containers, prune images/networks | **No** |
| Lateral movement | Build/run arbitrary containers on host network | **No** |
| Host filesystem access | `docker run -v /:/host` from worker | **No** |
| Unrestricted network | Worker could launch containers on default bridge, bypassing `--internal` intent | **No** |

Root cause: **conflation of roles** — the same worker that executes untrusted assessment code also holds the keys to the host Docker daemon. The principle of least privilege is violated: the worker needs only a narrow subset of the Docker API (build a single image, run one container, clean up), yet receives the full socket.

---

## 3. Solution Comparison

| Solution | What it does | Isolation gained | Effort | Breaks current execution? | 8GB RAM laptop viable? | Production readiness |
|----------|--------------|------------------|--------|---------------------------|------------------------|----------------------|
| **A. Docker socket proxy** (e.g. `docker-socket-proxy`) | Sidecar on worker host; worker mounts proxy socket; whitelisted API routes only (`/build`, `/containers/*`, `/networks/*`, `/images/*` read) | Worker cannot `exec`, mount arbitrary host volumes, run `--privileged`, or touch other containers | Low/Medium | No (repoint socket mount to proxy socket) | **Yes** | Staging-ready; good defense-in-depth but still shares host kernel |
| **B. Separate runtime host/service** | Worker submits build/run jobs to a dedicated runtime service over a restricted API; worker never touches `dockerd` | Worker compromise does not directly compromise host Docker | Medium/High | **Yes** — requires runtime service + worker re-architecture | No (needs 2 hosts/VMs locally) | Production-ready for multi-tenant |
| **C. Rootless Docker** | `dockerd` runs as non-root user; socket owned by that user | Reduces blast radius if worker compromised (no root on host), but socket compromise still grants container control within that user | Medium | Partially (rootless has build/run limitations) | Yes | Moderate — reduces but does not eliminate risk |
| **D. gVisor (`runsc`)** | User-space kernel intercepts syscalls; containers run with `runtime=runsc` | Strong syscall isolation; no direct host-kernel syscalls from target | Medium | Partially (orchestrator must specify runtime; build still uses dockerd) | **Marginal** — adds ~100–200MB RAM per container; OK on 8GB for light use | Strong sandbox for targets; does not fix worker↔dockerd boundary alone |
| **E. Kata Containers** | OCI containers backed by lightweight VMs (guest kernel per container) | Hardware-level VM isolation; guest-kernel escape does not compromise host kernel | High | **Yes** — runtime swap + orchestration changes | **No** — each Kata VM needs its own RAM; too heavy for 8GB laptop | Production-grade for untrusted multi-tenant code |
| **F. Firecracker microVMs** | Minimal guest kernels, ~5ms boot, KVM | Strongest isolation; purpose-built for untrusted serverless workloads | High | **Yes** — requires Firecracker VMM + API shim | **No** — needs KVM + dedicated infra; too heavy locally | Production-grade; AWS-curated |

### Key distinction: target isolation vs. worker boundary

- **gVisor/Kata/Firecracker** harden the **target container** (kernel escape resistance). They do **not** by themselves remove the worker's direct `dockerd` access. A compromised worker can still issue `docker stop`, `docker rm`, or launch privileged containers regardless of the target runtime.
- **Socket proxy** and **separate runtime host** address the **worker↔dockerd privilege boundary**, which is the actual gap in the current design.
- **Rootless Docker** reduces the blast radius of the socket but the worker can still control containers as its own user.

---

## 4. Build-Time vs. Runtime Networking

Docker networking has two distinct phases, both currently weak:

### 4.1 Build-time networking (`docker build`)
- **Before commit `be08ad3`:** `docker build --network=host` — build ran on the host network with no isolation. A malicious `Dockerfile`/`requirements.txt` could reach the LAN, metadata endpoints, or sibling services during the build.
- **After `be08ad3`:** `--network=host` removed; build uses the default bridge. The default bridge **does not** provide outbound isolation by default — containers on it can reach external networks unless `--internal` or custom firewall rules are applied. Build-time network isolation is therefore **not yet enforced**.
- **Remaining gap:** No `--internal` equivalent for `docker build`; no restriction on `RUN curl/wget` in user Dockerfiles during build.

### 4.2 Runtime networking (`docker run`)
- Target containers use `docker network create --internal` + `-p=127.0.0.1:<host>:<app>`. This is sound **for the target**, but `--internal` only affects the `FORWARD` chain (external forwarding). The host bridge gateway IP (`172.x.0.1`) is reachable from the container via the host `INPUT` chain. Host services bound to `0.0.0.0` are reachable from targets unless host firewall (`iptables INPUT -i br-+`) blocks them.
- The API container is dual-homed on `sentinelx-internal` and `sentinelx-public` networks (compose). Targets are on per-assessment `--internal` networks — separation is maintained at the Docker network layer, but the API's public exposure is now loopback-only (commit `be08ad3`).

---

## 5. Risks Involving Docker Operations

| Risk area | Current state | Risk if worker compromised |
|-----------|--------------|----------------------------|
| Image builds | `docker build` on default bridge (post-fix) | Malicious Dockerfile exfiltrates build env, reaches LAN/metadata during build |
| Container creation | Hardened `docker run` args | Worker could bypass hardening via direct socket (`--privileged`, `-v /:/host`) |
| Volume mounts | None in target run (good) | Worker could add `-v` host paths via direct socket |
| Privileged flags | Not used in target run | Worker could run `--privileged` via direct socket |
| Host paths | Not mounted into targets | Worker could mount host paths via direct socket |
| Network config | `--internal` per-assessment network | Worker could attach containers to default bridge / host network |
| Docker API access | Full socket (root worker) | Complete host Docker control |

---

## 6. Development / Staging / Production Requirements

| Environment | Docker socket acceptable? | Recommended runtime | Rationale |
|-------------|--------------------------|---------------------|-----------|
| **Local development** (8GB RAM laptop) | Acceptable **only** if host is dedicated dev machine, no other prod services | Current socket mount + socket proxy (optional) | Developer trusts their own host; low cost; Firecracker/Kata too heavy |
| **Staging** | Not acceptable unmediated | Socket proxy + dedicated VM, or separate runtime host | Staging mirrors prod; validate proxy allowlisting before prod |
| **Multi-tenant production** | **Unacceptable** | Separate runtime host or microVM runtime (Kata/Firecracker) + socket proxy defense-in-depth | Untrusted public users; kernel escape must not reach prod host |

---

## 7. Recommended Architecture

### Phase 1 (immediate, low effort): Docker socket proxy
Deploy `docker-socket-proxy` (Teonite) as a sidecar on the worker host. Worker mounts only the proxy socket:
```yaml
services:
  docker-socket-proxy:
    image: tecnativa/docker-socket-proxy:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      AUTHORIZE_BUILD: 1
      AUTHORIZE_NETWORKS_CREATE: 1
      AUTHORIZE_NETWORKS_DELETE: 1
      AUTHORIZE_CONTAINERS_CREATE: 1
      AUTHORIZE_CONTAINERS_START: 1
      AUTHORIZE_CONTAINERS_STOP: 1
      AUTHORIZE_CONTAINERS_DELETE: 1
      AUTHORIZE_CONTAINERS_LOGS: 1
      AUTHORIZE_IMAGES_DELETE: 1
      AUTHORIZE_INFO: 1
      # Explicitly denied by omission:
      # AUTHORIZE_CONTAINERS_EXEC, AUTHORIZE_CONTAINERS_PAUSE, AUTHORIZE_VOLUMES_*, AUTHORIZE_IMAGES_PUSH, etc.
    networks:
      - sentinelx-internal
  worker:
    volumes:
      - docker-socket-proxy:/var/run/docker.sock:ro  # proxy socket, NOT host socket
```
- **Isolation gained:** Worker cannot `exec`, mount host volumes, run privileged, or touch sibling containers. Limited to the exact API surface the orchestrator uses.
- **Does not:** protect against host-kernel escape by a malicious target (still needs gVisor/Kata for that); does not isolate build network.

### Phase 2 (staging/pre-prod): Separate runtime host or rootless Docker
- Move execution to a dedicated runtime host (no other production workloads).
- Or run dockerd rootless so the worker socket maps to a non-root `dockerd`, reducing host blast radius.

### Phase 3 (multi-tenant production): MicroVM runtime
- Replace Docker target execution with Kata Containers or Firecracker on a dedicated runtime host, accessed via a restricted API service (Phase B architecture).
- Target-container kernel escape can no longer reach the host kernel.

### Build-time networking fix (all phases)
- Add `--network=none` or a dedicated `--internal` build network for `docker build`, OR restrict outbound via host firewall. Prevent `RUN curl/wget` in user Dockerfiles from reaching metadata/LAN during build. This is a separate gap from the socket mount.

---

## 8. Migration Steps (do not implement without approval)

1. **Document current socket risk** (already done in `DOCKER_AND_RUNTIME.md` §6 and compose comment — commit `be08ad3`).
2. **Add `docker-socket-proxy` service** to `docker-compose.yml` with strict allowlist.
3. **Re-point worker volume mount** from host socket to proxy socket.
4. **Run backend test suite** (tests mock Docker; socket-proxy change is infra-level) + static checks to confirm no regression.
5. **Validate locally** that `provision` works through the proxy (build, run, cleanup all succeed via proxy).
6. **For staging/prod:** provision dedicated runtime host; evaluate rootless Docker or microVM runtime based on tenant trust model.

## 9. Implementation Effort Estimate

| Phase | Work | Effort |
|-------|------|--------|
| 1 — Socket proxy + compose re-point | Compose edit, proxy allowlist tuning, local validation | ~1–2 days |
| 2 — Separate runtime host / rootless | Infra provisioning, worker re-pointing, network redesign | ~1–2 weeks |
| 3 — MicroVM (Kata/Firecracker/gVisor) | Runtime swap, orchestrator `runtime=` support, CI changes | ~3–6 weeks |
| Build-time network isolation | `--internal`/none build network or host firewall rules | ~1–2 days |

## 10. Security Trade-Offs

- **Socket proxy:** Defense-in-depth, low effort, preserves existing execution, but still shares the host kernel and dockerd. A kernel exploit in a target container can reach the host; not sufficient alone for untrusted multi-tenant code.
- **Separate runtime host:** Removes worker↔dockerd boundary entirely; highest practical isolation without microVMs; requires operational complexity (second host, network between worker and runtime).
- **Rootless Docker:** Reduces privilege but not API surface; rootless build has known limitations (overlayfs, port mapping below 1024).
- **gVisor/Kata/Firecracker:** Strongest target isolation; highest infra cost; do **not** fix the socket boundary by themselves. Best combined with Phase 1 or 2.

## 11. Test Plan

| Test | Type | What it verifies |
|------|------|------------------|
| Proxy allowlist unit test | Unit | `docker-socket-proxy` config blocks `exec`, `volumes`, `privileged`, `push` |
| Integration: build/run/cleanup via proxy | Integration (needs Docker) | Orchestrator works through proxy socket |
| Negative: worker cannot `docker exec` / `-v /:/host` | Security | Socket proxy denies disallowed operations |
| Build-time network: no `--network=host`, default bridge not assumed isolated | Static + integration | Build does not use host network; outbound restricted |
| Target `--internal` network + loopback bind | Existing unit tests | Already passing (test_docker_runtime_isolation.py) |
| Live Docker isolation | Blocked locally (no daemon access) | Mark BLOCKED until Docker available |

## 12. Local Development (8GB / ~5.7GB RAM laptop) vs. Dedicated Production Infrastructure

| Achievable locally (this laptop) | Requires dedicated production infra |
|----------------------------------|-------------------------------------|
| Socket proxy validation (single worker, light containers) | Multi-tenant isolation |
| Rootless Docker trial | Kata/Firecracker microVMs (per-VM RAM too heavy) |
| Full backend + frontend test suite | Live Docker daemon isolation verification (daemon unavailable here) |
| Build-time `--network=host` removal validation | Staging/prod rollout of socket proxy or separate runtime host |

Note: This environment has ~5.7GB RAM total and no Docker daemon access, so live Docker isolation testing and microVM evaluation cannot be performed here. Firecracker/Kata are explicitly **not** recommended for local validation on this hardware.

---

**Bottom line:** The socket mount must not be removed without a replacement, because `provision_runtime` (and pipeline cleanup) require Docker API access. The realistic first step is a **Docker socket proxy with strict API allowlisting** (Phase 1), preserving execution while removing the most dangerous socket operations. MicroVM runtimes (gVisor/Kata/Firecracker) harden targets but do not fix the worker boundary alone and are too heavy for this 8GB laptop.

**Awaiting approval before implementing the selected architecture.**
