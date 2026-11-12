# SENTINEL-X Architecture Specification

## 1. System Planes

The platform is partitioned into two distinct operational planes:

### 1.1 The Control Plane (FastAPI)
The control plane handles user interactions, identity verification, metadata management, and pipeline orchestration.
- **Components**: `app.main`, `app.api.v1`, `app.core.security`, `app.models`.
- **Boundaries**: Operates in a secure server context with database access.
- **Constraint**: The control plane **never** executes repository code directly or launches untrusted processes.

### 1.2 The Execution Plane (Celery / Background Workers)
The execution plane performs the computational and analysis heavy lifting.
- **Components**: `app.workers.assessment_tasks`, `app.services.assessment_pipeline`, `app.integrations.*`.
- **Isolation**: Workers operate in sandboxed Linux namespaces with isolated workspace mounts (`/var/lib/sentinelx/workspaces/{id}`).
- **Communication**: Tasks are queued via Redis and persist results to PostgreSQL through SQLAlchemy ORM sessions.

```
+-------------------------------------------------------------------+
|                        CONTROL PLANE                              |
|  [React Frontend] <---> [FastAPI Gateway] <---> [PostgreSQL 16]   |
+---------------------------------+---------------------------------+
                                  | Redis Task Queue
+---------------------------------v---------------------------------+
|                        EXECUTION PLANE                            |
|                                                                   |
|  [Celery Worker]                                                  |
|       |---> Git Shallow Clone into /workspaces/{id}/source        |
|       |---> Semgrep SAST & Gitleaks Secret Detection              |
|       |---> Syft CycloneDX SBOM & Grype Vulnerability Matching    |
|       |---> Docker Orchestrator (cap_drop=ALL, cgroups)           |
|       |---> OWASP ZAP & Native Security Probes                    |
|       |---> NetworkX Dependency Graph & Risk Engine               |
|       |---> OpenRouter LLM Remediation with Prompt Guards         |
|       +---> SARIF 2.1.0, JSON, CSV & PDF Report Generators        |
+-------------------------------------------------------------------+
```
