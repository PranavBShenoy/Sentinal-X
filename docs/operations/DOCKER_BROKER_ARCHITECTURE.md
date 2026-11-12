# SENTINEL-X — Docker Privilege Boundary: Constrained Runtime Broker Architecture

**Status:** Proposed architecture — awaiting implementation (this document is the design).
**Branch:** `fix/security-hardening-audit` (HEAD `be08ad3`, not pushed)
**Problem:** The Celery worker runs as root with an unmediated `/var/run/docker.sock` mount. A compromised worker gains full control of the host Docker daemon. A conventional socket proxy allowlist is NOT sufficient because an allowed container-creation endpoint can still accept dangerous configurations (privileged, host mounts, host network, host PID, exec).

## 1. Design Principle: Policy-Enforcing Broker

The Docker socket must never be mounted into the Celery worker. Instead, a **separate Runtime Broker service** holds the socket and enforces a strict security policy on every request. The broker decides the security parameters; the caller (worker/orchestrator) only sends minimal, validated operational parameters. The broker rejects any request that would create a privileged, host-mounted, host-networked, or exec-accessible container.

A socket proxy may be added later as defense-in-depth, but it is **not** the sole security boundary — the broker is.

## 2. Architecture Separation

| Component | Docker Socket | Talks To | Trust Boundary |
|-----------|--------------|----------|----------------|
| Celery Worker | **None** | Broker (HTTP, authenticated) | Untrusted — executes assessment code |
| Runtime Broker | Mounted (read-only) | dockerd directly | Trusted — policy enforcement point |
| Socket Proxy (optional, future) | Mounted | Broker | Additional layer only |

```
Celery Worker                      Runtime Broker                    Host Docker
  (no socket)                          (socket)                          daemon
      |                                  |                                  |
      |-- HTTP + X-Broker-Key ---------->|                                  |
      |  (minimal validated params)      |  [POLICY ENFORCEMENT]            |
      |                                  |-- docker build/run/rm ---------->|
      |<-- status / target_url ----------|                                  |
      |                                  |                                  |
  Assessment pipeline (provision_runtime)  Cleanup on finally/cancel       |
```

## 3. Broker Requirements (all enforced by broker, not caller)

The broker exposes **only** the operations SENTINEL-X requires. Every request is validated against a strict Pydantic schema. Arbitrary Docker API parameters are rejected.

| Requirement | Enforcement |
|-------------|-------------|
| Specific operations only | Fixed endpoint set; no passthrough to arbitrary Docker API |
| Strict schema validation | Pydantic models; unknown fields rejected |
| No arbitrary Docker API params | Caller sends only `{image_tag, container_name, network_name, app_port, host_port, workspace_path}` |
| Reject privileged | Hardcoded `--privileged` never allowed; `privileged` field absent from schema |
| Reject host filesystem mounts | No `volumes`/`bind mounts` accepted; broker never mounts host paths |
| Reject host networking | `network_mode=host` rejected; only `--internal` bridge networks |
| Reject host PID namespace | `pid_mode=host` rejected; absent from schema |
| Enforce non-root | Broker forces non-root user from image; `user=root` never accepted |
| Enforce cap_drop | Broker hardcodes `--cap-drop=ALL` |
| Enforce no-new-privileges | Broker hardcodes `--security-opt=no-new-privileges:true` |
| Enforce resource limits | Broker hardcodes memory=512m, cpus=1.0, pids-limit=100 |
| Approved image/build-context | Image tags must match `sentinelx-app-<assessment>`; build context must be under `ASSESSMENT_WORKSPACE_BASE` |
| Network restrictions | `--internal` network; port binding `127.0.0.1` only; no `0.0.0.0` |
| Controlled cleanup | Broker owns container/network/image removal; worker triggers by assessment ID |
| Prevent exec | No `/exec` endpoint exposed |
| Worker-to-broker auth | `X-Broker-Key` header validated against shared `BROKER_API_KEY` |

## 4. Broker Endpoints

All endpoints require `X-Broker-Key` authentication.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/broker/build` | Build image from validated workspace |
| POST | `/v1/broker/network/create` | Create `--internal` network |
| POST | `/v1/broker/container/run` | Run hardened container (policy-enforced) |
| GET | `/v1/broker/container/logs/{name}` | Get redacted container logs |
| POST | `/v1/broker/container/stop` | Stop container |
| DELETE | `/v1/broker/container/{name}` | Remove container |
| DELETE | `/v1/broker/network/{name}` | Remove network |
| DELETE | `/v1/broker/image/{tag}` | Remove image |
| POST | `/v1/broker/cleanup` | Full assessment cleanup (container→network→image) |
| GET | `/v1/broker/health` | Broker liveness |

**No exec endpoint. No privileged flag. No volume/mount parameters. No network_mode=host. No pid_mode=host.**

## 5. Build-Time Security

`docker build` currently (after prior fix) uses the default bridge, which provides **no** outbound isolation. The broker enforces:
- `--network=none` or a dedicated internal build network for `docker build` (no `--network=host`, no default bridge outbound)
- Build context restricted to `ASSESSMENT_WORKSPACE_BASE`
- Image tag naming policy: `sentinelx-app-<assessment_id>` only
- No arbitrary build args accepted from caller

## 6. Exact Files to Change

### New files
1. `backend/app/runtime/broker/__init__.py` — package marker
2. `backend/app/runtime/broker/schemas.py` — Pydantic request/response schemas (strict validation)
3. `backend/app/runtime/broker/auth.py` — `X-Broker-Key` authentication dependency
4. `backend/app/runtime/broker/policy.py` — security policy enforcement (reject dangerous configs, hardcode safe params)
5. `backend/app/runtime/broker/executor.py` — Docker CLI wrapper executed by the broker (subprocess-based, consistent with existing code)
6. `backend/app/runtime/broker/app.py` — FastAPI broker application with all endpoints
7. `backend/app/runtime/broker/client.py` — `BrokerClient` used by the orchestrator (HTTP + auth, fail-closed)
8. `backend/app/runtime/broker/server.py` — uvicorn entrypoint
9. `backend/tests/unit/test_broker_auth.py` — auth tests
10. `backend/tests/unit/test_broker_policy.py` — policy rejection tests (privileged, host mounts, host network, host PID, exec, root user, arbitrary params)
11. `backend/tests/unit/test_broker_schemas.py` — schema validation tests
12. `backend/tests/unit/test_broker_client.py` — client fail-closed / auth tests
13. `backend/tests/integration/test_orchestrator_broker.py` — orchestrator→broker integration (mocked broker)

### Modified files
14. `backend/app/runtime/docker/orchestrator.py` — replace direct `docker` CLI calls with `BrokerClient`; preserve `provision()`/`cleanup()`/`is_docker_available()` interface; fail closed when broker unavailable
15. `backend/app/core/config.py` — add `BROKER_URL`, `BROKER_API_KEY`, `BROKER_AUTH_REQUIRED`, `BUILD_NETWORK_MODE`
16. `docker-compose.yml` — add `broker` service (socket mounted), remove socket mount from `worker`, worker `BROKER_URL=http://broker:8001`
17. `backend/tests/integration/test_docker_runtime_isolation.py` — update assertions to reflect broker-based execution; add broker policy tests

## 7. Interface Preservation

The `RuntimeOrchestrator` public interface is preserved:
- `provision(assessment_id, workspace_path) -> Dict[str, Any]`
- `cleanup(assessment_id) -> None`
- `is_docker_available() -> bool`

Internally, it now delegates to `BrokerClient` instead of shelling out to `docker` directly. Existing callers (`assessment_pipeline.py`, `assessment_tasks.py`, `endpoints/assessments.py`, `endpoints/runtime.py`) require no changes.

## 8. Failure Modes

| Scenario | Behavior |
|----------|----------|
| Broker unreachable (production) | Fail closed — `provision()` returns `FAILED`; no direct docker fallback |
| Broker unreachable (dev) | Fail closed — same; dev must run broker locally |
| Dangerous config requested | Broker returns `400` with policy violation; no container created |
| Auth key missing/invalid | Broker returns `401` |
| Build timeout | Broker returns error; orchestrator cleans up partial image |
| Container start failure | Broker returns error; orchestrator cleans up network + image |
| Health check failure | Orchestrator triggers full cleanup via broker |
| Interrupted job / timeout | `finally:` block in pipeline calls `cleanup()` → broker removes container/network/image |

## 9. Security Trade-offs

- **Broker + socket** still shares the host kernel with targets. A container-escape exploit can reach the host kernel. This is mitigated by (a) non-root, cap-drop, no-new-privileges, read-only rootfs; (b) future microVM runtime (gVisor/Kata/Firecracker) — **not claimed as implemented** unless actually integrated.
- The broker itself is a trusted component; it must run on a dedicated/isolated host in production.
- Socket proxy (optional future) adds defense-in-depth but is not relied upon as the boundary.

## 10. Local Development vs. Production

| | Local Dev (this laptop) | Production |
|---|---|---|
| Docker daemon | Unavailable here — live Docker tests BLOCKED | Available |
| Broker testing | Unit tests (no Docker) + mocked integration | Live broker + live Docker |
| Worker socket mount | None (talks to broker) | None (talks to broker) |
| Broker socket mount | N/A (no Docker locally) | Mounted (read-only) |
| Fail-closed on broker down | Tested via mocks | Live behavior |
