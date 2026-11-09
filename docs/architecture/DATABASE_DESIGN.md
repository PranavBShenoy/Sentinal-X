# SENTINEL-X — Database Design & Schema Architecture

SENTINEL-X uses a relational PostgreSQL schema (with full SQLite compatibility for fast hermetic local and CI testing) managed by Alembic migrations (`migrations/versions/1dca02b9811e_initial_schema.py`).

## 1. Entity-Relationship Overview

```mermaid
erDiagram
    USERS ||--o{ PROJECTS : "owns"
    USERS ||--o{ USER_SESSIONS : "authenticates"
    USERS ||--o{ AUDIT_LOGS : "triggers"
    PROJECTS ||--o{ REPOSITORIES : "contains"
    PROJECTS ||--o{ ASSESSMENTS : "tracks"
    REPOSITORIES ||--o{ ASSESSMENTS : "targets"
    ASSESSMENTS ||--o{ SCAN_JOBS : "executes"
    ASSESSMENTS ||--o{ FINDINGS : "produces"
    ASSESSMENTS ||--o{ SBOM_COMPONENTS : "contains"
    ASSESSMENTS ||--o{ DEPENDENCY_EDGES : "maps"
    ASSESSMENTS ||--o{ REMEDIATION_PROPOSALS : "generates"
    ASSESSMENTS ||--o{ REPORTS : "exports"
    FINDINGS ||--o{ REMEDIATION_PROPOSALS : "remediates"

    USERS {
        uuid id PK
        string email UK
        string username UK
        string hashed_password
        string full_name
        boolean is_active
        boolean is_superuser
        boolean is_verified
        timestamp created_at
        timestamp updated_at
    }

    PROJECTS {
        uuid id PK
        uuid owner_id FK
        string name
        string description
        string slug
        jsonb settings
        timestamp created_at
        timestamp updated_at
    }

    REPOSITORIES {
        uuid id PK
        uuid project_id FK
        string full_name
        string clone_url
        string default_branch
        boolean is_private
        string encrypted_access_token
        timestamp created_at
    }

    ASSESSMENTS {
        uuid id PK
        uuid project_id FK
        uuid repository_id FK
        uuid created_by_id FK
        string status
        string branch
        string commit_sha
        string target_url
        string current_stage
        integer progress_percentage
        float overall_risk_score
        string risk_level
        jsonb config
        jsonb repo_analysis
        timestamp started_at
        timestamp completed_at
    }

    FINDINGS {
        uuid id PK
        uuid assessment_id FK
        uuid scan_job_id FK
        string fingerprint UK
        string title
        text description
        string category
        string subcategory
        string severity
        string status
        string confidence
        string source_tool
        string rule_id
        string file_path
        integer line_start
        integer line_end
        float cvss_score
        float risk_score
        jsonb cve_ids
        jsonb advisory_ids
        text ai_explanation
        text ai_impact
        text ai_remediation_steps
    }

    SBOM_COMPONENTS {
        uuid id PK
        uuid assessment_id FK
        string name
        string version
        string purl
        string ecosystem
        boolean is_direct
        jsonb vulnerability_matches
    }

    DEPENDENCY_EDGES {
        uuid id PK
        uuid assessment_id FK
        string source_purl
        string target_purl
        string relationship_type
    }

    REPORTS {
        uuid id PK
        uuid assessment_id FK
        string format
        string file_path
        integer file_size
        string sha256_hash
        timestamp generated_at
    }
```

---

## 2. Multi-Tenant Isolation Guarantees
- **Strict Row-Level Authorization**: All API controllers verify that `Project.owner_id == current_user.id` or that the user has explicit project-level permissions.
- **Cascading Referential Integrity**: Deleting a project cascades cleanly across all child repositories, assessments, scan jobs, findings, SBOM components, and reports.
- **Tenant Boundary Tests**: Verified by `tests/integration/test_tenant_isolation_deep.py` and `tests/integration/test_projects_api.py`. A tenant can never query, mutate, or trigger assessments against another tenant's project or repository.

## 3. Cryptographic Storage & Masking
- **Fernet Encryption at Rest**: Encrypted database fields (such as repository OAuth tokens and deploy credentials) utilize standard AES-128-CBC with HMAC-SHA256 authenticated encryption (`app.core.security.encrypt_symmetric`).
- **Secret Redaction**: Any secret discovered by Gitleaks or raw scanner logs is permanently masked before persistence via `SecretMasker` and `mask_secret` regex algorithms.
