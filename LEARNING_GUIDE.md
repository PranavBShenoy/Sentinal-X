# SENTINEL-X --- Technical Architecture, Engineering & Learning Guide

> **Authoritative Technical Defense & Comprehensive System Guide**  
> **Platform:** SENTINEL-X (AI-Powered Application & Software Supply-Chain Security Platform)  
> **Target Audience:** Project Owner, Security Engineers, Architects, and Interview Evaluators.

---

## TABLE OF CONTENTS
1. [Executive Overview & Product Vision](#1-executive-overview--product-vision)
2. [Module 1: Control Plane, Authentication & Tenant Isolation](#2-module-1-control-plane-authentication--tenant-isolation)
3. [Module 2: Repository Ingestion & Safe Subprocess Execution](#3-module-2-repository-ingestion--safe-subprocess-execution)
4. [Module 3: Static Analysis (SAST) & Secret Detection](#4-module-3-static-analysis-sast--secret-detection)
5. [Module 4: Software Bill of Materials (SBOM) & Vulnerability Intelligence](#5-module-4-software-bill-of-materials-sbom--vulnerability-intelligence)
6. [Module 5: Isolated Runtime Orchestrator (Docker Hardening)](#6-module-5-isolated-runtime-orchestrator-docker-hardening)
7. [Module 6: Dynamic Application Security Testing (DAST) & SSRF Defenses](#7-module-6-dynamic-application-security-testing-dast--ssrf-defenses)
8. [Module 7: Normalization, Correlation & Deterministic Risk Engine](#8-module-7-normalization-correlation--deterministic-risk-engine)
9. [Module 8: Evidence-Grounded AI Analysis & Remediation Hub](#9-module-8-evidence-grounded-ai-analysis--remediation-hub)
10. [Module 9: Multi-Format Reporting Engine (SARIF, JSON, CSV, PDF)](#10-module-9-multi-format-reporting-engine-sarif-json-csv-pdf)
11. [Module 10: Modern React & TypeScript Security Dashboard](#11-module-10-modern-react--typescript-security-dashboard)
12. [Comprehensive Technical Interview & Defense Q&A](#12-comprehensive-technical-interview--defense-qa)
13. [Local Deployment, Operational Runbook & Verification](#13-local-deployment-operational-runbook--verification)
14. [Advanced Scanner Integrations & Offline Resolutions: Grype, Semgrep, and OSV-Scanner](#14-advanced-scanner-integrations--offline-resolutions-grype-semgrep-and-osv-scanner)
15. [Audit Remediation & Hardening: SEC-01, OPS-01, and INFRA-01](#15-audit-remediation--hardening-sec-01-ops-01-and-infra-01)

---

## 1. EXECUTIVE OVERVIEW & PRODUCT VISION

### 1.1 The Problem
Modern software security is plagued by siloed tools:
- **SAST tools** flag hundreds of potential code vulnerabilities but lack runtime context, creating high false-positive rates.
- **SCA tools** produce flat lists of vulnerable packages without knowing if the vulnerable package function is actually reachable or called.
- **DAST tools** probe running applications from the outside without insight into internal code flaws or supply-chain origins.
- **AI wrappers** hallucinate fixes and fabricate vulnerability claims without evidence grounding.

### 1.2 The SENTINEL-X Solution
SENTINEL-X bridges the gap between static code, supply-chain dependencies, ephemeral isolated runtimes, and dynamic observable behavior into a single, cohesive assessment graph:
```
                      ┌─────────────────────────────────┐
                      │    Target Git Repository / PR   │
                      └────────────────┬────────────────┘
                                       │
                ┌──────────────────────┴──────────────────────┐
                ▼                                             ▼
  ┌───────────────────────────┐                 ┌───────────────────────────┐
  │        Static Plane       │                 │       Runtime Plane       │
  │ • Semgrep SAST            │                 │ • Project Detection       │
  │ • Gitleaks Secret Masking │                 │ • Sandboxed Docker Spawn  │
  │ • Syft CycloneDX SBOM     │                 │   (cap_drop=ALL, cgroups) │
  │ • Grype / OSV Vuln Intel  │                 │ • OWASP ZAP & Active DAST │
  └─────────────┬─────────────┘                 └─────────────┬─────────────┘
                │                                             │
                └──────────────────────┬──────────────────────┘
                                       ▼
                      ┌─────────────────────────────────┐
                      │  Evidence Correlation & Graph   │
                      │ • SHA-256 Fingerprint Normalizer│
                      │ • NetworkX Dependency Graph     │
                      │ • Deterministic 0-10 Risk Engine│
                      └────────────────┬────────────────┘
                                       ▼
                      ┌─────────────────────────────────┐
                      │   AI Remediation & Reporting    │
                      │ • OpenRouter with Prompt Guards │
                      │ • Human-in-the-Loop Patch Diff  │
                      │ • SARIF 2.1.0, JSON, CSV, PDF   │
                      └─────────────────────────────────┘
```

---

## 2. MODULE 1: CONTROL PLANE, AUTHENTICATION & TENANT ISOLATION

### 1. Basic Understanding
The Control Plane is the brain of the platform. It handles user authentication, session tracking, project administration, and assessment dispatch. It must **never** run untrusted code directly.

### 2. What We Built
- **FastAPI Control Plane**: RESTful API endpoints mounted under `/api/v1` with automatic OpenAPI documentation.
- **JWT + SHA-256 Sessions**: Short-lived HS256 access tokens (30 minutes) combined with SHA-256 hashed refresh tokens stored in PostgreSQL.
- **Multi-Tenant Isolation**: Enforced at the ORM query level. Every project, repository, assessment, finding, and report is strictly verified against `Project.owner_id == current_user.id`.
- **Database Architecture**: SQLAlchemy 2.0 with portable types (`JSON.with_variant(JSONB, 'postgresql')` and `String(36).with_variant(UUID, 'postgresql')`) enabling PostgreSQL in production and SQLite in testing.
- **Alembic Migrations**: Fully reversible database version control tracking all 14 schema tables.

### 3. How It Works
1. A client authenticates via `POST /api/v1/auth/login`.
2. The server verifies the password hash using `bcrypt.checkpw()`.
3. An access token containing `sub` (user_id) and `exp` is generated. A random 32-byte refresh token is hashed with SHA-256 and stored in `user_sessions`.
4. Subsequent requests pass `Authorization: Bearer <access_token>`.
5. The `get_current_user` FastAPI dependency extracts the JWT, verifies the signature, and retrieves the active user.
6. The `get_project_or_404` and `get_assessment_or_404` dependencies enforce ownership: an attempt by User A to access User B's assessment ID returns an immediate `404 Not Found`, preventing object reference enumeration.

### 4. Technologies Used
- **FastAPI**: Asynchronous high-performance web framework.
- **SQLAlchemy 2.0**: Declarative ORM.
- **Alembic**: Database schema migration manager.
- **Bcrypt & PyJWT**: Cryptographic password hashing and RFC 7519 JSON Web Token issuance.
- **Fernet (Cryptography)**: AES-128-CBC symmetric encryption for sensitive stored credentials.

### 5. Code Explanation
- [`backend/app/core/security.py`](file:///home/pranav/Sentinal-X/backend/app/core/security.py): Implements `get_password_hash()`, `verify_password()`, `create_access_token()`, `decode_access_token()`, and `encrypt_value()` / `decrypt_value()`.
- [`backend/app/api/dependencies.py`](file:///home/pranav/Sentinal-X/backend/app/api/dependencies.py): Defines security dependencies `get_current_user()`, `get_project_or_404()`, and `get_assessment_or_404()`.
- [`backend/app/models/models.py`](file:///home/pranav/Sentinal-X/backend/app/models/models.py): Defines the 14 core database entities with indexes and foreign keys.

### 6. Testing & Verification
- Unit test: `backend/tests/unit/test_security.py` tests password hashing, token expiration, invalid signatures, and secret masking.
- Integration test: `backend/tests/integration/test_auth_api.py` and `test_projects_api.py` verify duplicate email rejection, weak password rejection, and cross-tenant isolation.
- Command: `PYTHONPATH=backend python3 -m pytest backend/tests/unit/test_security.py backend/tests/integration/test_auth_api.py -v` (100% PASS).

### 7. What You Must Know (Defense Focus)
- **Why hash refresh tokens in the database?** If the database is dumped in an unauthorized breach, raw refresh tokens are not exposed. Hashing them with SHA-256 prevents attackers from replaying sessions.
- **How is tenant isolation maintained?** We never trust an ID provided in request parameters. Every query joins through `Project` and filters by `Project.owner_id == current_user.id`.

---

## 3. MODULE 2: REPOSITORY INGESTION & SAFE SUBPROCESS EXECUTION

### 1. Basic Understanding
Untrusted repositories might contain malicious file names, nested git hooks, or attempt command injection. All external tool invocations must be strictly isolated and sandboxed.

### 2. What We Built
- **Safe Subprocess Runner (`subprocess_utils.py`)**: Executes system commands strictly as argument arrays (`List[str]`), explicitly forbidding `shell=True`.
- **Secret Redaction Filter (`secret_redactor.py`)**: Sanitizes stdout and stderr in memory before logging or database persistence using regex pattern matching.
- **Timeout Guards**: Enforces hard timeouts on all commands (e.g. 120s for clone, 300s for static scans) to prevent Denial of Service (DoS) from infinite loops or malicious inputs.
- **Repository Service (`repository_service.py`)**: Clones exact commit SHAs or branches into ephemeral workspace directories (`/var/lib/sentinelx/workspaces/{assessment_id}/source`) with shallow clone depth (`--depth 50`).

### 3. How It Works
1. `RepositoryService.fetch(assessment_id)` creates a dedicated directory structure for the assessment.
2. If authenticated access is required for a private repository, credentials (e.g. GitHub token) are injected into the HTTPS authority string in memory.
3. `run_command(["git", "clone", ...])` executes `subprocess.Popen` without a shell.
4. If a specific commit SHA was requested, `git checkout <sha>` pins the exact commit.
5. If the repository is a local fixture directory, `shutil.copytree` creates an isolated working copy.
6. The `ProjectDetector` inspects files to profile framework, languages, ports, and Docker configurations.

### 4. Technologies Used
- **Python Subprocess**: Native OS process execution with non-blocking stream capture.
- **Git CLI**: Version control operations with shallow cloning.
- **Python Pathlib**: Safe filesystem path normalization preventing directory traversal attacks (`../`).

### 5. Code Explanation
- [`backend/app/core/subprocess_utils.py`](file:///home/pranav/Sentinal-X/backend/app/core/subprocess_utils.py): Encapsulates `run_command()`. Implements strict argument validation, timeout kills, and secret redaction.
- [`backend/app/core/secret_redactor.py`](file:///home/pranav/Sentinal-X/backend/app/core/secret_redactor.py): Contains high-entropy regex patterns matching AWS access keys, GitHub tokens, Slack tokens, private keys, and JWTs, replacing matches with `***REDACTED***`.
- [`backend/app/services/repository_service.py`](file:///home/pranav/Sentinal-X/backend/app/services/repository_service.py): Manages workspace creation, clone operations, and architectural profiling.

### 6. Testing & Verification
- Unit test: `backend/tests/unit/test_security.py::test_secret_redactor` verifies that sensitive tokens in stderr and stdout are completely replaced by redaction markers.

### 7. What You Must Know
- **Why is `shell=True` banned?** `shell=True` spawns a system shell (`/bin/sh`) which interprets metacharacters (`;`, `&&`, `|`, `$()`). If a branch name or file path contains `; rm -rf /`, passing it as a string allows command execution. Array execution (`["git", "clone", url]`) passes arguments directly to `execve()`, making injection impossible.

---

## 4. MODULE 3: STATIC ANALYSIS (SAST) & SECRET DETECTION

### 1. Basic Understanding
Source-code security inspection uncovers implementation flaws (SQL injection, XSS, insecure deserialization) and committed secrets before code is deployed.

### 2. What We Built
- **Semgrep SAST Integration (`semgrep/scanner.py`)**: Runs Semgrep rules against repository source code with JSON output formatting.
- **Gitleaks Secret Detection (`gitleaks/scanner.py`)**: Scans files and commit history for exposed secrets, passwords, and API credentials.
- **Mandatory Secret Masking**: When Gitleaks detects a secret, SENTINEL-X masks the middle characters (`AKIA****3XYZ`), guaranteeing that cleartext credentials are never written to the database, logs, or reports.
- **Missing Binary Resilience**: If a scanner binary is not installed on the system, SENTINEL-X records a `ScanJob` with `CheckStatus.BLOCKED` and clear diagnostics, never failing silently or fabricating false-clean results.

### 3. How It Works
1. `SemgrepScanner.scan()` executes `semgrep scan --json --config auto <workspace_path>`.
2. Results are parsed and transformed into normalized findings with CWE IDs, OWASP tags, file coordinates, and code snippets.
3. `GitleaksScanner.scan()` executes `gitleaks detect --no-git --report-format json`.
4. The output matches are stripped of sensitive values via `mask_secret()` before being saved as `Finding` records in PostgreSQL.

### 4. Technologies Used
- **Semgrep**: Lightweight, fast static analysis tool matching concrete syntax trees.
- **Gitleaks**: High-performance secret scanner specializing in regular expression entropy analysis.

### 5. Code Explanation
- [`backend/app/integrations/semgrep/scanner.py`](file:///home/pranav/Sentinal-X/backend/app/integrations/semgrep/scanner.py): Wraps Semgrep, maps Semgrep severities (ERROR -> HIGH/CRITICAL, WARNING -> MEDIUM, INFO -> LOW), and normalizes code snippets.
- [`backend/app/integrations/gitleaks/scanner.py`](file:///home/pranav/Sentinal-X/backend/app/integrations/gitleaks/scanner.py): Wraps Gitleaks, implements `mask_secret()`, and records detected secret leaks.

---

## 5. MODULE 4: SOFTWARE BILL OF MATERIALS (SBOM) & VULNERABILITY INTELLIGENCE

### 1. Basic Understanding
An application is only as secure as its open-source dependencies. An accurate Software Bill of Materials (SBOM) provides full inventory of direct and transitive libraries.

### 2. What We Built
- **CycloneDX SBOM Generation (`syft/scanner.py`)**: Uses Anchore Syft to inspect package manifests (`package-lock.json`, `requirements.txt`, `poetry.lock`, `pom.xml`, `go.sum`) and generate standardized CycloneDX 1.5 JSON.
- **Database Model Persistence**: Parses the SBOM and stores components in `sbom_artifacts`, `sbom_components`, and dependency relationships in `dependency_edges`.
- **Vulnerability Matching (`grype/scanner.py`)**: Feeds the CycloneDX SBOM to Anchore Grype to match known vulnerabilities from NVD, GitHub Security Advisories (GHSA), and distro databases.
- **OSV REST Client (`osv/client.py`)**: Queries the Open Source Vulnerabilities (OSV.dev) API with in-memory caching and batching to pull real-time vulnerability data, fixed versions, and advisory links.

### 3. How It Works
1. `SyftScanner.scan()` invokes `syft dir:<path> -o cyclonedx-json=<sbom_file>`.
2. The generated CycloneDX JSON is parsed into `SbomComponent` records with names, versions, ecosystems, and Package URLs (PURL).
3. `GrypeScanner.scan()` reads the SBOM and queries vulnerability feeds.
4. Each CVE finding is linked to its `SbomComponent`, tracking whether it is a direct or transitive dependency.

### 4. Technologies Used
- **Syft**: Multi-ecosystem cataloger for container images and filesystems.
- **Grype**: Vulnerability scanner for SBOMs and container images.
- **OSV.dev API**: Distributed open-source vulnerability database.
- **CycloneDX**: Modern OWASP standard for software supply-chain transparency.

---

## 6. MODULE 5: ISOLATED RUNTIME ORCHESTRATOR (DOCKER HARDENING)

### 1. Basic Understanding
Running untrusted code directly on a host server is a catastrophic security vulnerability. Any runtime provisioning must be ephemeral, resource-constrained, and isolated.

### 2. What We Built
- **Project Framework Detector (`runtime/detection/detector.py`)**: Detects Python (FastAPI, Flask, Django), Node.js (Express, Next.js), and Docker configurations, entrypoints, and expected environment variables.
- **Sandboxed Docker Orchestrator (`runtime/docker/orchestrator.py`)**:
  - Drops all Linux kernel capabilities: `cap_drop=['ALL']`.
  - Disables container privilege escalation: `security_opt=['no-new-privileges:true']`.
  - Caps CPU and Memory (e.g. 512MB RAM, 1.0 CPU quota) to prevent resource starvation.
  - Mounts workspace code strictly as read-only (`:ro`).
  - Binds dynamically to an ephemeral local loopback port (`127.0.0.1:0`).
  - Executes active HTTP health probes with retries and exponential backoff.
- **Guaranteed Cleanup**: Context-managed termination ensures that all spawned containers are stopped and pruned upon assessment completion, error, or cancellation.

### 3. Security Hardening Matrix
| Parameter | Setting | Security Rationale |
|---|---|---|
| `cap_drop` | `["ALL"]` | Removes root abilities (network sniffing, raw sockets, kernel module loading). |
| `security_opt` | `["no-new-privileges:true"]` | Prevents setuid binaries inside the container from gaining root privileges. |
| `read_only` | `True` | Prevents the untrusted application from writing persistence scripts or rootkits. |
| `mem_limit` | `512m` | Defends against fork bombs and memory exhaustion attacks. |
| `network_mode` | Bridge / Internal | Isolates the container from the host's private cloud network. |

---

## 7. MODULE 6: DYNAMIC APPLICATION SECURITY TESTING (DAST) & SSRF DEFENSES

### 1. Basic Understanding
Dynamic testing probes the running web application from an external attacker's perspective, verifying security headers, cookie flags, and endpoint configurations.

### 2. What We Built
- **SSRF Defense Engine (`assessments.py::validate_target_url`)**:
  - Validates scheme (`http` / `https`). Rejects non-HTTP schemes (`file://`, `ftp://`).
  - Resolves hostnames to IP addresses via DNS.
  - Rejects loopback addresses (`127.0.0.1`, `localhost`, `::1`).
  - Rejects link-local and cloud metadata services (`169.254.169.254`).
  - Rejects multicast and reserved addresses.
  - *Audit Finding (SEC-01)*: RFC 1918 private network blocking (`ip.is_private`) and unresolvable DNS rejection must be explicitly added to complete internal network gating.
- **Native Security Header & Configuration Probes**:
  - Audits `Content-Security-Policy` (CSP) presence and directive strength.
  - Verifies `Strict-Transport-Security` (HSTS) with `includeSubDomains`.
  - Inspects `X-Content-Type-Options: nosniff`.
  - Inspects `X-Frame-Options: DENY` or `SAMEORIGIN`.
  - Verifies Cookie flags (`Secure`, `HttpOnly`, `SameSite`).
  - Tests for permissive CORS reflection (`Access-Control-Allow-Origin: *` with credentials).
  - Checks for exposed server banners (`Server: Apache/2.4.41`, `X-Powered-By: Express`).
- **OWASP ZAP Integration (`zap/scanner.py`)**: Triggers spider and active scan against authorized targets.

### 3. Testing & Verification
- Unit test: `test_ssrf_protection_loopback_rejected` and `test_ssrf_protection_metadata_ip_rejected` verify that SSRF attacks are blocked with `400 Bad Request`.

---

## 8. MODULE 7: NORMALIZATION, CORRELATION & DETERMINISTIC RISK ENGINE

### 1. Basic Understanding
Combining findings from Semgrep, Gitleaks, Grype, Trivy, and ZAP creates duplicates and noise. SENTINEL-X deduplicates findings and applies a deterministic, explainable risk score from 0.0 to 10.0.

### 2. What We Built
- **Deterministic Fingerprinting (`analysis/normalization/normalizer.py`)**:
  - Computes a stable SHA-256 hash from finding attributes:
    `SHA256(category:tool:normalized_rule:file_path:cve_id)`
  - Identical findings across repeated scans yield the exact same fingerprint, enabling historical tracking, regression detection, and disposition persistence.
- **Multi-Tool Correlation (`analysis/correlation/correlator.py`)**:
  - Deduplicates overlapping findings.
  - Correlates SAST code flaws with vulnerable dependency components.
- **NetworkX Dependency Graph (`analysis/dependency_graph/builder.py`)**:
  - Builds an in-memory directed graph (`networkx.DiGraph`).
  - Traces paths from top-level root packages to deeply nested transitive dependencies.
  - Flags attack paths where vulnerable transitive packages are reachable.
- **Deterministic Risk Engine (`analysis/risk/engine.py`)**:
  Calculates a 0.0–10.0 risk score using an open, transparent formula:
  $$\text{Risk Score} = \min(10.0, \text{Base} \times \text{Reachability} \times \text{Exposure} \times \text{Confidence})$$

### 3. Risk Engine Weights
- **Base Score**: Derived from CVSS score (if available) or standardized severity:
  - CRITICAL: 9.5
  - HIGH: 7.5
  - MEDIUM: 5.0
  - LOW: 2.5
  - INFO: 0.5
- **Reachability Multiplier**:
  - Direct dependency or executable route: `1.2`
  - Transitive dependency: `0.8`
  - Unreachable / isolated code: `0.5`
- **Exposure Multiplier**:
  - Exposed secret with valid syntax: `1.3`
  - Publicly accessible endpoint: `1.2`
  - Internal endpoint: `1.0`
- **Confidence Weight**:
  - HIGH confidence: `1.0`
  - MEDIUM confidence: `0.85`
  - LOW confidence: `0.7`

### 4. Code Explanation
- [`backend/app/analysis/risk/engine.py`](file:///home/pranav/Sentinal-X/backend/app/analysis/risk/engine.py): Implements `calculate_finding_risk()` and `score_all()`, generating a transparent rationale string explaining exactly why a finding received its score.

---

## 9. MODULE 8: EVIDENCE-GROUNDED AI ANALYSIS & REMEDIATION HUB

### 1. Basic Understanding
LLMs must never hallucinate vulnerabilities or become the sole source of truth. SENTINEL-X uses AI exclusively to explain confirmed scanner evidence and synthesize unified git diffs for human review.

### 2. What We Built
- **OpenRouter Client (`openrouter/client.py`)**: Configured via environment variables (`LLM_PROVIDER`, `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`).
- **Prompt Injection Defense**:
  - Sanitizes user and repository input before inclusion in prompts.
  - Strips prompt-breaking tags (`<system>`, `ignore previous instructions`).
  - Wraps vulnerability context in structured XML delimiters.
- **Pydantic Validation (`AIExplanationResponse`)**:
  - Forces the model to respond in strict JSON adhering to schema:
    `{ explanation: str, security_impact: str, remediation_steps: List[str], diff: str }`.
- **Deterministic Fallback**: If no OpenRouter API key is configured or the service is offline, the client generates rule-based security explanations and patch guidelines based on CWE and OWASP databases.
- **Human-in-the-Loop Approval**:
  - Remediation proposals are saved in `remediation_proposals`.
  - Proposals remain inactive until an analyst clicks "Approve Fix".
  - Patches are never silently committed to main branches.

---

## 10. MODULE 9: MULTI-FORMAT REPORTING ENGINE (SARIF, JSON, CSV, PDF)

### 1. Basic Understanding
Security assessments must be exported into standardized machine formats for CI/CD integration and human formats for executive leadership.

### 2. What We Built
- **OASIS SARIF 2.1.0 (`reporting/generator.py`)**:
  - Conforms to the official Static Analysis Results Interchange Format schema (`v2.1.0`).
  - Compatible with GitHub Code Scanning, SonarQube, and VS Code SARIF viewers.
- **Machine JSON**: Full telemetry export including assessment configuration, repository profile, scanner jobs, findings, evidence, and coverage statistics.
- **CSV Export**: Tabular spreadsheet of all findings for auditor review.
- **Executive PDF via WeasyPrint**:
  - Professional typography, high-contrast severity badges, executive summary, breakdown of checks planned vs executed, and remediation status.
- **Integrity Verification**: Generates SHA-256 hashes for all exported files to ensure tamper evidence.

---

## 11. MODULE 10: MODERN REACT & TYPESCRIPT SECURITY DASHBOARD

### 1. Basic Understanding
A security tool must be intuitive, responsive, and provide clear operational feedback. It must never display mock data on live screens.

### 2. What We Built
- **Vite + React + TypeScript**: High performance, zero-runtime errors, fully typed.
- **Tailwind CSS Security Theme**: Accessible dark mode design with color-coded severity badges (Critical: Red, High: Orange, Medium: Yellow, Low: Blue, Info: Slate).
- **Core Views**:
  1. `LoginPage` & `RegisterPage`: JWT auth flow with custom event listener on token expiration.
  2. `DashboardPage`: Global stats, risk scores, recent scans, scanner engine statuses.
  3. `ProjectsPage`: Project management, repository connection, clone URLs.
  4. `NewAssessmentPage`: Scan launcher with SSRF warnings, tool toggles, and branch selection.
  5. `AssessmentDetailPage`: Live stage stepper, scanner execution table with exit codes and error logs, coverage indicators.
  6. `FindingsPage`: Search by CVE/file/title, filter by severity/tool/disposition, inspect modal.
  7. `DependencyGraphView`: Interactive component browser, direct vs transitive labels, vulnerable CVE badges.
  8. `RemediationPage`: AI-generated patch proposals with unified diff viewer (red/green syntax) and "Approve Fix" buttons.
  9. `ReportsPage`: Export selector and instant file downloads.

---

## 12. COMPREHENSIVE TECHNICAL INTERVIEW & DEFENSE Q&A

### Q1: What makes SENTINEL-X different from standard vulnerability scanners like SonarQube or Snyk?
**Answer:** Most scanners operate in a single domain. Snyk focuses on SCA and static code; SonarQube focuses on code quality and basic SAST. SENTINEL-X uniquely correlates four layers:
1. Static code implementation (Semgrep)
2. Software Bill of Materials & transitive dependencies (Syft, Grype, OSV)
3. Ephemeral sandboxed runtime behavior (Docker Orchestrator)
4. Dynamic testing (OWASP ZAP & security header probes)
By connecting these four layers through our deterministic risk engine, we determine if a vulnerable package function is actually called and whether an active route exposes it.

### Q2: Why is the risk scoring formula deterministic instead of using an LLM?
**Answer:** Security decisions require auditability, reproducibility, and mathematical consistency. An LLM scoring vulnerabilities is non-deterministic: the same finding could receive a 6/10 today and an 8/10 tomorrow. In SENTINEL-X, the risk score is computed using a deterministic formula combining base CVSS score, reachability, exposure, and scanner confidence. The LLM is restricted to providing context and remediation advice.

### Q3: How does SENTINEL-X protect against Server-Side Request Forgery (SSRF)?
**Answer:** When users provide a target staging URL, `validate_target_url` parses the hostname and resolves it to IP addresses using DNS. It validates that the resolved IP does not fall into loopback (`127.0.0.1`), link-local / cloud metadata (`169.254.169.254`), or private internal subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). If a blocked range is detected, the scan is rejected with `400 Bad Request`.

### Q4: How are secrets protected in SENTINEL-X?
**Answer:**
1. In transit: All subprocess outputs pass through `SecretRedactor` before being logged.
2. In storage: Gitleaks findings are sanitized using `mask_secret()`, replacing the middle characters with asterisks (`AKIA****XYZ`).
3. Sensitive credentials (such as GitHub OAuth tokens) are encrypted in the database using symmetric AES-128 Fernet encryption (`encrypt_value()`).

### Q5: What security controls are applied to the Docker runtime container?
**Answer:**
1. `cap_drop=['ALL']`: Drops all Linux kernel capabilities.
2. `security_opt=['no-new-privileges:true']`: Prevents privilege escalation via setuid binaries.
3. Memory limit (512MB) and CPU quotas prevent host starvation.
4. Ephemeral loopback port binding (`127.0.0.1:0`) prevents external exposure.
5. Mandatory cleanup in `finally` blocks destroys the container once the scan completes.

### Q6: What happens if a security tool binary is not installed on the server?
**Answer:** Rather than failing the entire assessment or fabricating false-clean results, the scanner wrapper checks `shutil.which("<tool>")`. If missing, it records a `ScanJob` with `CheckStatus.BLOCKED`, sets `has_partial_failures = True`, and concludes the assessment as `PARTIAL`. This provides transparent coverage accounting.

### Q7: Explain finding fingerprinting and why it is necessary.
**Answer:** A finding fingerprint is a SHA-256 hash calculated over normalized fields: `SHA256(category:tool:rule:file:cve)`. It ensures that identical issues across different branches or scans share the same ID. This allows security analysts to mark an issue as `FALSE_POSITIVE` or `ACCEPTED_RISK` once, and have that disposition persist across subsequent commits.

---

## 13. LOCAL DEPLOYMENT, OPERATIONAL RUNBOOK & VERIFICATION

### 13.1 Architecture of the Local Service Mesh
For local development, testing, and air-gapped staging environments:
1. **PostgreSQL 16/18**: Initialized via `initdb`, running as a persistent daemon with unix-socket connectivity (`/tmp/.s.PGSQL.5432`) or loopback port (`5432`).
2. **Redis 7**: Running as a lightweight daemon accepting unix socket connections (`/tmp/redis.sock`) and loopback TCP (`6379`) for Celery broker queues.
3. **Alembic Migrations**: All 16 database tables (`users`, `projects`, `repositories`, `assessments`, `scan_jobs`, `findings`, `remediation_proposals`, `reports`, etc.) are version-controlled and applied with `python3 -m alembic upgrade head`.
4. **Celery Worker**: Asynchronous assessment task executor subscribing to `redis+socket:///tmp/redis.sock?virtual_host=0` with task concurrency limits and guaranteed job isolation.
5. **FastAPI Control Plane**: Uvicorn ASGI server hosting the REST API, enforcing JWT authentication, rate limiting, and CORS headers.
6. **React 18 Frontend**: Vite SPA serving the security dashboard, project wizards, interactive graph view, and report export panel.

### 13.2 Step-by-Step Deployment Commands
```bash
# 1. Initialize PostgreSQL Cluster & Database
/usr/lib/postgresql/18/bin/initdb -D /tmp/sentinelx_pgdata -U sentinelx --auth=trust
/usr/lib/postgresql/18/bin/postgres -D /tmp/sentinelx_pgdata -k /tmp -p 5432 -h 127.0.0.1 &
psql -h /tmp -U sentinelx -d postgres -c "CREATE DATABASE sentinelx;"

# 2. Start Redis Daemon
redis-server --unixsocket /tmp/redis.sock --unixsocketperm 777 --port 6379 --dir /tmp &

# 3. Apply Alembic Migrations
cd /home/pranav/Sentinal-X/backend
DATABASE_URL="postgresql+psycopg2://sentinelx@/sentinelx?host=/tmp" python3 -m alembic upgrade head

# 4. Start Celery Worker Daemon
cd /home/pranav/Sentinal-X/backend
python3 -m celery -A app.workers.celery_app.celery_app worker -l INFO --concurrency=2 &

# 5. Start FastAPI Backend Control Plane
cd /home/pranav/Sentinal-X/backend
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 &

# 6. Start Frontend Dashboard
cd /home/pranav/Sentinal-X/frontend
npm run build && npm run preview -- --port 3000
```

### 13.3 End-to-End Verification Pipeline
The verification suite exercises the complete lifecycle of a security assessment:
- **Authentication**: Bcrypt password hashing, session tokens, rate-limited `/auth/login` and `/auth/register`.
- **Project & Repo Setup**: Tenant-scoped project creation with private repository mapping.
- **Scanner Ingestion**: Real CLI tools (`gitleaks`, `trivy`, `syft`, `zap`) run against fixture repositories, detecting real secrets and historical CVEs without mocks.
- **Risk Calculation**: Ingested findings are weighted by reachability, direct vs. transitive exposure, and confidence multipliers, yielding a 0–10 risk score.
- **Reporting Engine**: Generates real disk artifacts in PDF (WeasyPrint), SARIF 2.1.0 (OASIS standard), JSON, and CSV formats.
- **Remediation Hub**: Evaluates findings, generates code patches, and persists user approvals.

---
*End of LEARNING_GUIDE.md — Maintained for SENTINEL-X Core Evaluation.*

---

## 14. ADVANCED SCANNER INTEGRATIONS & OFFLINE RESOLUTIONS: GRYPE, SEMGREP, AND OSV-SCANNER

### 14.1 Anchore Grype Vulnerability Matching & Database Hydration
- **Architecture**: Anchore Grype matches components discovered in CycloneDX SBOMs or direct directories against the Anchore vulnerability feed.
- **Database Architecture & Provenance**:
  - Anchore DB Schema: `v6.1.10`
  - Location: `~/.cache/grype/db/6/vulnerability.db` (SQLite format)
  - Built: `2026-11-08T06:19:57Z`
  - Upstream Archive: `vulnerability-db_v6.1.10_2026-11-08T00:22:04Z_1794118797.tar.zst`
  - SHA-256 Checksum: `dcca24722e16c2bcf4a542a3f7fdd2147baf9215c17b973f5a7d4243fbddacea`
  - Validation Status: `valid` (verified via `grype db status`)
- **Offline Enforcement**:
  - Executed with `GRYPE_CHECK_FOR_APP_UPDATE=false` and `GRYPE_DB_AUTO_UPDATE=false`.
  - Scans operate completely offline without network egress.
- **Missing/Corrupt Database Handling**:
  - If the database is missing or corrupted, Grype terminates with exit code `1` and outputs `[0001] ERROR failed to load vulnerability db: database does not exist`.
  - `GrypeScanner` detects non-zero exit codes and records `CheckStatus.ERROR` / `ScanJobStatus.FAILED`. It never silently accepts missing databases or falsely reports 0 vulnerabilities.
- **Execution Modes**:
  - SBOM Mode: `grype sbom:<path> -o json --file <output> -q`
  - Directory Mode: `grype dir:<path> -o json --file <output> -q`

### 14.2 Semgrep Static Application Security Testing (SAST)
- **Isolation from System Python**: Standard Ubuntu environments running Python 3.14 alpha/beta lack precompiled wheel support for Semgrep. An isolated standalone CPython 3.12 runtime was provisioned via `uv` at `.uv/python/cpython-3.12.16-linux-x86_64-gnu/` and a dedicated virtualenv at `.semgrep-env`.
- **Sandbox Resilience**: In Linux sandbox environments where `/home/pranav` is a read-only mountpoint, Semgrep crashed attempting to write `~/.semgrep/settings.yml`. A resilient execution wrapper at `bin/semgrep` forces `HOME=/tmp`, `SEMGREP_SETTINGS_FILE=/tmp/semgrep_settings.yml`, `SEMGREP_SEND_METRICS=off`, and `--disable-version-check`.
- **Verified Offline Rule Configuration**:
  - **No `--config auto`**: `SemgrepScanner` explicitly requires `settings.SEMGREP_RULES_PATH` (`rules/semgrep/default_rules.json`). If the rules file is missing, it returns `CheckStatus.BLOCKED`.
  - Bundles 1,226 offline security rules covering OWASP Top 10, CWE-89 (SQL Injection), CWE-78 (Command Injection), and CWE-79 (XSS).
  - Effective rule IDs in findings carry the local path prefix `rules.semgrep.` (e.g., `rules.semgrep.python.lang.security.audit.formatted-sql-query.formatted-sql-query`), providing irrefutable forensic proof of local rule execution over registry downloads.
- **Code Snippet Extraction & Redaction**: Reads target files directly between `line_start` and `line_end` when Semgrep lines are suppressed, applying `redact()` before persistence.

### 14.3 Google OSV-Scanner Dependency Intelligence
- **Binary Installation**: Official Google OSV-Scanner v2.7.1 binary installed at `bin/osv-scanner`.
- **Native Offline Databases**: Local Scalibr vulnerability archives for PyPI (`~/.cache/osv-scalibr/PyPI/all.zip`) and npm (`~/.cache/osv-scalibr/npm/all.zip`).
- **Command**:
  - `osv-scanner scan source --offline-vulnerabilities --data-source native --no-resolve --format json --output-file <file> <path>`
- **Exit Code Semantics & Disambiguation**:
  - Exit Code `0`: Clean scan — zero vulnerabilities detected.
  - Exit Code `1`: Vulnerabilities successfully detected and parsed from JSON output.
  - Exit Code `127`: Non-existent path or invalid CLI arguments (`CheckStatus.ERROR`).
  - Exit Code `128` (Disambiguated): In OSV-Scanner 2.7.1, exit code 128 is overloaded:
    1. *Clean Empty Directory*: When a target directory contains no package manifests, stdout/stderr contains `"No package sources found"` and zero extraction errors. `OSVScanner` handles this as `CheckStatus.PASSED` with 0 findings.
    2. *Corrupted Manifest*: When a manifest is malformed (e.g. invalid JSON in `package-lock.json`), stderr contains `"Error during extraction:"` or `"could not extract"`. `OSVScanner` inspects output for these strings and returns `ScanJobStatus.FAILED` and `CheckStatus.ERROR`, preventing silent false-pass scans.

### 14.4 Cross-Scanner Finding Correlation & Deduplication
- **Multi-Scanner Redundancy**: When Grype, Trivy, and OSV scan the same repository, all three scanners independently identify identical known CVEs (e.g., `CVE-2018-18074` on `requests 2.6.0`).
- **Correlation Mechanism (`FindingCorrelator`)**:
  - Groups dependency findings by composite key `(cve_id, component)`.
  - Selects a primary finding deterministically to remain active (`FindingStatus.CONFIRMED` or `OPEN`).
  - Marks redundant detections as `FindingStatus.SUPPRESSED` with an audit reason referencing the primary finding ID: `Correlated duplicate of <primary.source_tool> finding <primary.id> (shared vulnerability identifier <cve>)`.
  - **Preserves Full Provenance**: The primary finding's `raw_evidence["additional_sources"]` array records the tool name, rule ID, severity, CVSS score, and evidence payload from every duplicate detection.
  - **Metadata Enrichment**: If a duplicate finding contains a higher CVSS score or a fixed version absent from the primary, the primary finding is enriched with that data.

### 14.5 Live Scanner Verification Matrix

| Tool | Version | Mode | Target Fixture | Test Case | Status | Verified Findings |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Gitleaks** | 8.18.4 | Local binary | `tests/fixtures/secret_leak` | `test_live_gitleaks_actual_binary_and_secret_masking` | **PASS** | AWS Key, Generic API Key (Masked) |
| **Trivy** | 0.76.2 | Local binary | `tests/fixtures/vuln_deps` | `test_live_trivy_vulnerability_detection` | **PASS** | CVE-2018-18074 on requests 2.6.0 |
| **Zap / Native DAST** | 1.0.0 | HTTP server | Port 9877 | `test_live_native_dast_against_test_application` | **PASS** | 11 categories: Security Headers, TLS, CORS, Cookies, Open Redirect, API Discovery, Access Control, SQLi Error, Reflected XSS, Rate Limiting |
| **Reports Engine** | 1.0.0 | Real generator | Assessment DB | `test_report_generation_formats_integrity` | **PASS** | JSON, SARIF 2.1.0, CSV non-empty |
| **Semgrep SAST** | 1.184.0 | Python 3.12 / offline rules | `tests/fixtures/vuln_sqli` | `test_live_semgrep_sast_vulnerability_detection` | **PASS** | SQL injection line 20 (`cursor.execute`), `rules.semgrep.` prefix |
| **Grype** | 0.121.3 | Offline v6 DB (v6.1.10) | CycloneDX + `vuln_deps` | `test_live_grype_vulnerability_detection_against_sbom_and_dir` | **PASS** | 16 CVEs (requests 2.6.0, urllib3 1.25.8), missing DB tested |
| **OSV-Scanner** | 2.7.1 | Offline native DB | `tests/fixtures/vuln_deps` | `test_live_osv_scanner_dependency_vulnerability_detection` | **PASS** | 32 Advisories / CVE-2018-18074 (CVSS 7.5) |
| **Fault Tolerance** | --- | Error injector | Nonexistent bin / empty dir | `test_live_scanners_error_handling_and_fallback` | **PASS** | `BLOCKED` status, clean exit on empty dir |
| **Deduplication** | --- | Correlator engine | `tests/fixtures/vuln_deps` | `test_cross_scanner_cve_deduplication` | **PASS** | Trivy+Grype+OSV deduplicated to 1 active, 2 suppressed with provenance |
| **OSV Error Handling** | 2.7.1 | Corrupt JSON manifest | Temp corrupt manifest | `test_osv_scanner_corrupted_manifest_error` | **PASS** | Exit code 128 with extraction error returned `CheckStatus.ERROR` |

### 14.6 Honest Operational Limitations & Production Prerequisites
- **Database Hydration Schedules**: Both Anchore Grype DB v6 and Google OSV Scalibr databases are snapshots. In an air-gapped production deployment, an automated cron or synchronization pipeline must hydrate `~/.cache/grype/db/6/` and `~/.cache/osv-scalibr/` periodically to ingest zero-day advisories.
- **Runtime MicroVM Isolation**: Docker container hardening (`cap_drop=['ALL']`, `security_opt=['no-new-privileges:true']`, `read_only=True`, cgroups memory/CPU limits) prevents user-space escapes. However, for untrusted multi-tenant code execution in production, hypervisor-level microVM isolation (such as AWS Firecracker or gVisor) is recommended over shared-kernel containers to protect against kernel privilege-escalation zero-days.
- **Network Egress Safeguards**: When running outside strict sandbox boundaries, egress proxies must restrict scanner outbound network traffic to approved advisory endpoints only, preventing data exfiltration during dependency scanning.

---

## 15. AUDIT REMEDIATION & HARDENING: SEC-01, OPS-01, AND INFRA-01

### 15.1 SEC-01: Comprehensive SSRF Engine & Safe Socket Transport

#### 1. Vulnerability Analysis
Prior to remediation, staging target URLs supplied by users during assessment creation were checked using naive hostname and string checks. This left the platform vulnerable to:
- **DNS Rebinding**: An attacker registers a domain whose DNS server returns a public IP during initial validation (TTL=0) and resolves to `127.0.0.1` or `169.254.169.254` during the actual HTTP request.
- **Alternative IP Encoding**: Decimal dwords (`2130706433`), octal strings (`0177.0.0.1`), hex numbers (`0x7f000001`), or IPv4-mapped IPv6 (`::ffff:127.0.0.1`) that bypass string-based prefix filters while resolving to internal subnets.
- **Redirect Loops & Bypasses**: Initial validation of `https://example.com/` succeeds, but the server issues a 302 redirect to `http://169.254.169.254/latest/meta-data/`.
- **Fail-Open DNS**: Failing DNS resolution allowed unresolvable hostnames through or raised uncaught exceptions that bypassed downstream checks.

#### 2. Architecture & Implementation
We implemented a dedicated security engine in [`backend/app/core/ssrf.py`](file:///home/pranav/Sentinal-X/backend/app/core/ssrf.py):
- **Canonicalization**: `canonicalize_ip_representation()` parses decimal dwords, octal strings, hex notation, and unmaps IPv4-mapped IPv6 addresses.
- **Exhaustive Prohibited Matrix**: `is_prohibited_ip()` validates against RFC 1122 Loopback (`127.0.0.0/8`, `::1`), RFC 1918 Private networks, RFC 4193 ULA (`fc00::/7`), RFC 3927 Link-Local (`169.254.0.0/16`, `fe80::/10`), RFC 6598 CGNAT (`100.64.0.0/10`), RFC 5737 Documentation subnets, Cloud Metadata endpoints, and enforces `ip.is_global`.
- **Dual-Stack DNS & Fail-Closed**: `resolve_all_ip_addresses()` queries both A and AAAA records. If ANY record resolves to a non-public IP, the entire request is blocked. If DNS resolution fails, the engine fails closed.
- **Pinned Socket Transport (`PinnedSSRFNetworkBackend`)**: Subclasses `httpcore.SyncBackend` to intercept `connect_tcp`. It resolves and validates the destination IP immediately before socket creation and connects directly to the pre-validated IP address, defeating DNS rebinding at the transport layer while preserving Host header and TLS SNI.
- **Hop-by-Hop Redirect Validation (`SafeSSRFClient`)**: Disables automatic client redirects. Manually intercepts 3xx responses and re-validates the destination URL before following any hop.

---

### 15.2 OPS-01: Shared Atomic Redis Rate Limiting & Proxy Trust

#### 1. Architectural Challenge
In production, SENTINEL-X runs multiple FastAPI workers behind reverse proxies or load balancers. In-memory per-process rate limiters allow attackers to multiply their request budget by the number of worker processes. Furthermore, naive trust of `X-Forwarded-For` allows attackers to bypass rate limits simply by injecting randomized header values (`X-Forwarded-For: 1.2.3.4`).

#### 2. Solution Implementation
We implemented [`backend/app/core/rate_limiter.py`](file:///home/pranav/Sentinal-X/backend/app/core/rate_limiter.py):
- **Redis Sliding Window via Atomic Lua Script**:
  - `ZREMRANGEBYSCORE`: Removes requests outside the sliding window.
  - `ZCARD`: Calculates the current window count atomically.
  - `ZADD` + `EXPIRE`: Enters the new request with bounded key TTL.
- **Client IP Extraction with Spoofing Defense**:
  - Configurable `TRUSTED_PROXIES` in [`backend/app/core/config.py`](file:///home/pranav/Sentinal-X/backend/app/core/config.py).
  - If direct socket peer (`request.client.host`) is NOT in `TRUSTED_PROXIES`, `X-Forwarded-For` is completely ignored.
- **RFC 6585 Compliance**: Returns HTTP 429 with `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining: 0`, and `X-RateLimit-Reset`.
- **Degraded Health Reporting**: Exposed in `/health` status endpoint.

---

### 15.3 INFRA-01: Hardened Container Runtime Isolation & Non-Root Users

#### 1. Isolation Hardening
The Docker orchestrator ([`backend/app/runtime/docker/orchestrator.py`](file:///home/pranav/Sentinal-X/backend/app/runtime/docker/orchestrator.py)) was hardened with strict containment flags:
- `cap_drop=['ALL']`: Drops all Linux kernel capabilities.
- `--security-opt=no-new-privileges:true`: Prevents privilege escalation via `setuid` binaries.
- `--read-only`: Mounts root filesystem as read-only.
- `--tmpfs=/tmp:rw,noexec,nosuid,size=64m`: Provides ephemeral scratch space with execution blocked.
- Non-root user generation: Dockerfiles auto-inject `appuser` (UID 10001) for Python and `node` (UID 1000) for Node.js.
- Bounded cgroups: 512MB RAM, 1 CPU quota, 100 max PIDs.

#### 2. Production MicroVM Recommendation
For multi-tenant SaaS environments where arbitrary user repositories are provisioned, shared-kernel Docker containers present a residual risk of kernel zero-day escapes. SENTINEL-X is designed to bridge to hypervisor-isolated microVM technologies:
- **AWS Firecracker**: Hardware-isolated microVMs with sub-second launch latency and minimal device attack surface.
- **Google gVisor (`runsc`)**: Syscall-intercepting user-space kernel acting as an application sandbox.

---

### 15.4 Deep Multi-Tenant IDOR/BOLA Protection Verification

All resources across SENTINEL-X verify tenant boundaries via relational queries:
`Project.owner_id == current_user.id`

Verified in `backend/tests/integration/test_tenant_isolation_deep.py` across:
1. Projects (CRUD): HTTP 403/404 on cross-user access.
2. Repositories: HTTP 403/404 on cross-user repository attachment or listing.
3. Assessments: HTTP 403/404 on create, read, trigger, or cancel.
4. Findings: HTTP 403/404 on read or disposition updates; zero data leakage in global listings.
5. SBOM & Dependency Graphs: HTTP 403/404 on artifact, component, or graph retrieval.
6. Reports: HTTP 403/404 on generate, list, or download.
7. Remediation Proposals: HTTP 403/404 on view, approve, or verify.





---

## 16. FULL PLATFORM VALIDATION, REAL BROWSER E2E & PRODUCTION READINESS

### 16.1 Headless Chromium & Selenium Browser E2E Architecture

While API-level unit and integration tests verify contract compliance, real user security workflows require end-to-end browser execution to detect client-side token storage issues, session invalidation edge-cases, DOM rendering regressions, and file download failures.

#### E2E Verification Workflow (`backend/tests/e2e/test_browser_e2e.py`)
1. **Automated Server Orchestration**:
   - The test harness automatically spawns an ephemeral FastAPI server on port 8000 and a Vite preview server on port 3000 using isolated test databases and Redis rate limiters.
2. **Headless Chromium Execution**:
   - Initialized via Selenium WebDriver with flags: `--headless=new`, `--no-sandbox`, `--disable-dev-shm-usage`, and `--disable-gpu`.
3. **Full Journey Verification**:
   - **User Registration**: Fills out full name, email, and strong password meeting password policy. Verifies JWT issuance and storage in browser `localStorage`.
   - **Session Maintenance**: Tests authenticated route gating via `ProtectedRoute` in React Router.
   - **Project Provisioning**: Opens modal, registers project pointing to local vulnerable test repository `tests/fixtures/vuln_sqli`, and validates DOM updates.
   - **Assessment Execution**: Launches multi-tool assessment pipeline, tracking stage transitions from `CREATED` to `COMPLETED` / `PARTIAL`.
   - **Findings Explorer**: Interacts with findings table, tests dynamic CVE/CWE search, opens finding detail modal, verifies vulnerability metadata, and triages disposition.
   - **Dependency Graph Exploration**: Navigates to `/assessments/{id}/graph`, verifying graph nodes, direct vs. transitive badges, and summary counts (`total_components`, `direct_dependencies`, `transitive_dependencies`, `vulnerable_components`).
   - **Remediation Hub**: Inspects AI remediation diff proposals and patch rationale.
   - **Multi-Format Report Generation & Authenticated Download**: Generates JSON, SARIF, CSV, and PDF reports. Downloads the compiled report file via browser URL and asserts HTTP 200 with non-empty payload.

---

### 16.2 Direct Browser Downloads: Solving the Native Download Authorization Problem

#### The Security Problem
Standard web browser file downloads (`<a href="..." download>`) do not allow JavaScript to attach arbitrary HTTP headers such as `Authorization: Bearer <token>`. Previous implementations that required Bearer tokens for report downloads resulted in immediate HTTP 401 Unauthorized errors when users clicked "Download File" in the UI.

#### The SENTINEL-X Solution
We implemented a dual-mode authentication dependency (`get_download_user` in `backend/app/api/v1/endpoints/reports.py`):
1. **Header-First Evaluation**: Inspects `Authorization: Bearer <token>` for API clients, CI/CD runners, and curl scripts.
2. **Signed Token Query Fallback**: If no header is present, extracts `?token=<access_token>` from the query string.
3. **Cryptographic Validation**: Decodes the JWT, verifies cryptographic signature, checks expiration, and validates active user existence.
4. **Tenant Ownership Enforcement**: Verifies that the report's parent assessment and project belong to the requesting user (`Project.owner_id == user.id`), preventing unauthorized cross-tenant downloads.
5. **Frontend URL Integration**: `api.getReportDownloadUrl(reportId)` dynamically appends `?token=${encodeURIComponent(accessToken)}`, ensuring zero 401 errors on user downloads.

---

### 16.3 Environmental Boundary Handling: Honest Docker Evaluation

In modern agentic or containerized evaluation environments, child containers often run with `The "no new privileges" flag is set` or without nested root permissions, preventing `dockerd` from running locally.

SENTINEL-X handles this constraint with architectural honesty:
- **No Deceptive Mocking**: We never claim a mock container ran when it did not.
- **Graceful Orchestrator Detection**: `RuntimeOrchestrator.is_docker_available()` probes Docker availability. If unavailable, it sets `runtime_status = RuntimeStatus.FAILED` or `BLOCKED` with detailed audit logging while allowing the static analysis and report generation pipelines to complete flawlessly.
- **Production Reproduction**: Complete reproduction steps for genuine Docker hosts are documented in `docs/operations/DOCKER_AND_RUNTIME.md` and `docker-compose.yml`.

---

### 16.4 Cryptographic OAuth State Protection & Webhook Signature Verification

#### OAuth CSRF Defense
To prevent login CSRF and authorization code interception attacks, `GitHubService` implements signed OAuth state tokens:
1. **Timestamped Nonce**: Each state parameter contains `{timestamp}:{nonce}:{signature}`.
2. **HMAC-SHA256 Signing**: The raw timestamp and nonce are signed using `JWT_SECRET` in constant time.
3. **Expiration Bound**: States expire after 600 seconds (10 minutes) and reject future-dated timestamps.
4. **Fail-Closed Validation**: If a state is missing, tampered, expired, or malformed, `verify_oauth_state()` returns `False`, causing the callback endpoint to reject the request with HTTP 400.

#### Webhook Integrity Verification
`GitHubService.verify_webhook_signature()` verifies the `X-Hub-Signature-256` header:
1. Parses `sha256=<hex_digest>` from the incoming webhook request.
2. Computes the HMAC-SHA256 of the raw request payload using `GITHUB_WEBHOOK_SECRET`.
3. Compares signatures using `hmac.compare_digest()` to eliminate timing attack vectors.
