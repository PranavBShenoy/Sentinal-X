# SENTINEL-X — REST API Specification & Integration Guide

The SENTINEL-X REST API is mounted under prefix `/api/v1` and enforces standard HTTP status codes, Bearer JWT authentication, distributed sliding-window rate limiting, and tenant boundary verification.

---

## 1. Authentication Endpoints (`/api/v1/auth`)

### `POST /auth/register`
Creates a new tenant user account.
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "P@ssw0rd123!Secure",
    "full_name": "Security Analyst",
    "username": "analyst"
  }
  ```
- **Password Rules**: Minimum 12 characters; must contain uppercase, lowercase, numbers, and symbols.
- **Response** (`201 Created` or `200 OK`):
  ```json
  {
    "access_token": "<TOKEN_STRING>",
    "refresh_token": "<REFRESH_STRING>",
    "token_type": "bearer",
    "expires_in": 1800
  }
  ```

### `POST /auth/login`
Authenticates user and returns fresh session tokens.
- **Rate Limit**: 10 requests / minute per IP.
- **Response** (`200 OK`): Token response object with JWT access token.

### `GET /auth/me`
Retrieves authenticated user profile.
- **Headers**: `Authorization: Bearer <access_token>`

---

## 2. Projects & Repositories (`/api/v1/projects`)

### `GET /projects`
Lists all security projects owned by the authenticated tenant.
- **Query Params**: `page` (default 1), `page_size` (default 20).

### `POST /projects`
Creates a new security project.
- **Request Body**:
  ```json
  {
    "name": "Payment Gateway Service",
    "description": "Core payment processing microservice"
  }
  ```

### `POST /projects/{project_id}/repositories`
Registers a target git repository or local fixture for assessment.
- **Request Body**:
  ```json
  {
    "name": "payment-api",
    "clone_url": "https://github.com/org/repo.git",
    "default_branch": "main"
  }
  ```

---

## 3. Assessments & Scanning Pipeline (`/api/v1/assessments`)

### `POST /projects/{project_id}/assessments`
Creates a new security assessment configuration.
- **Request Body**:
  ```json
  {
    "repository_id": "<uuid>",
    "branch": "main",
    "commit_sha": "optional-sha",
    "config": {
      "target_url": "https://staging.example.com",
      "enable_sast": true,
      "enable_secrets": true,
      "enable_sbom": true,
      "enable_deps": true,
      "enable_runtime": true,
      "enable_dast": true
    }
  }
  ```

### `POST /assessments/{assessment_id}/start`
Enqueues and launches the multi-tool assessment pipeline.

### `GET /assessments/{assessment_id}/progress`
Returns live progress telemetry, current stage, and percentage.

---

## 4. Findings & Dependency Graphs

### `GET /findings`
Queries and filters normalized vulnerability findings.
- **Query Params**: `assessment_id`, `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), `category`, `status`, `search`.

### `PATCH /findings/{finding_id}/disposition`
Updates triage status with audit tracking.
- **Request Body**:
  ```json
  {
    "status": "FALSE_POSITIVE",
    "suppression_reason": "Compensating WAF rule in place",
    "notes": "Reviewed and validated by SecOps"
  }
  ```

### `GET /assessments/{assessment_id}/dependency-graph`
Returns directed acyclic graph (DAG) nodes, dependency relationships, and vulnerability indicators.

---

## 5. Reports & Compliance Exports (`/api/v1/reports`)

### `POST /assessments/{assessment_id}/reports/generate`
Compiles an assessment report.
- **Request Body**:
  ```json
  {
    "format": "json" // "json" | "sarif" | "csv" | "pdf"
  }
  ```

### `GET /reports/{report_id}/download`
Downloads the compiled compliance report.
- **Authentication**: Accepts standard `Authorization: Bearer <token>` header OR query parameter `?token=<access_token>` for seamless direct browser downloads.
- **Headers**: Returns `Content-Disposition: attachment; filename="report.<ext>"`.
