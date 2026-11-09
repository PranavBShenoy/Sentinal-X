# SENTINEL-X — Configuration Reference

This document provides the definitive configuration reference for all SENTINEL-X services, including the API Control Plane, Celery Worker, PostgreSQL, Redis, and React Frontend.

---

## 1. Core Platform Environment Variables

| Variable | Default Value | Description | Production Guidance |
| :--- | :--- | :--- | :--- |
| `APP_ENV` | `development` | Runtime environment (`development`, `staging`, `production`, `test`) | Set to `production` in production. Disables Swagger/OpenAPI docs. |
| `APP_HOST` | `0.0.0.0` | API bind address | Leave `0.0.0.0` inside containers. |
| `APP_PORT` | `8000` | API listening port | Container port 8000. |
| `LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | Use `INFO` in production, `DEBUG` during local triage. |
| `DATABASE_URL` | `postgresql+psycopg2://sentinelx:password@postgres:5432/sentinelx` | SQLAlchemy connection string | In production, use managed PostgreSQL 16+ with SSL mode. |
| `DATABASE_POOL_SIZE` | `20` | PostgreSQL connection pool size | Tune based on concurrent Celery workers and API replicas. |
| `DATABASE_MAX_OVERFLOW` | `10` | Allowed pool overflow connections | Recommended 5–10 for traffic bursts. |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis instance for rate limiting and cache | In production, use high-availability Redis with TLS and auth. |
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Celery task message broker | Dedicated Redis DB index (`/0`). |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/1` | Celery task result backend | Dedicated Redis DB index (`/1`). |
| `WORKER_CONCURRENCY` | `4` | Concurrency for Celery worker processes | Equal to allocated vCPUs. |
| `CELERY_TASK_ALWAYS_EAGER` | `false` | Run Celery tasks synchronously inline | Set to `true` exclusively for tests and single-process development. |

---

## 2. Cryptography & Authentication Settings

| Variable | Default Value | Description | Production Guidance |
| :--- | :--- | :--- | :--- |
| `JWT_SECRET` | `INSECURE_DEVELOPMENT_SECRET_CHANGE_IN_PRODUCTION` | Primary signing secret for HS256 JWT tokens | **MANDATORY**: Generate a minimum 32-byte cryptographically secure random string (`openssl rand -hex 32`). |
| `JWT_SECRET_KEY` | *(Mirrors JWT_SECRET)* | Backward-compatible alias for JWT signing secret | Automatically synced with `JWT_SECRET`. |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm | Standard HS256 HMAC signature. |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token lifespan in minutes | 15–30 minutes recommended. |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifespan in days | 7 days recommended. |
| `ENCRYPTION_KEY` | `""` | Fernet symmetric key for encrypting repository access tokens at rest | Generate via `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. |

---

## 3. Network, Rate Limiting & SSRF Defenses

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:3000` | Comma-separated list of allowed browser origins |
| `TRUSTED_PROXIES` | `127.0.0.1,::1` | Comma-separated list of reverse proxy IPs permitted to forward `X-Forwarded-For` headers |
| `RATE_LIMIT_ENABLED` | `true` | Enables distributed Redis sliding-window rate limiting |
| `ASSESSMENT_WORKSPACE_BASE` | `/tmp/sentinelx_workspaces` | Base path for isolated workspace checkouts and generated reports |

---

## 4. AI & Third-Party Integrations

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `LLM_PROVIDER` | `openrouter` | AI LLM provider engine (`openrouter`, `direct`, `mock`) |
| `OPENROUTER_API_KEY` | `""` | API key for OpenRouter models (`google/gemini-2.0-flash-001`, `anthropic/claude-3.5-sonnet`) |
| `OPENROUTER_MODEL` | `google/gemini-2.0-flash-001` | Default model for AI vulnerability explanations and unified diff patches |
| `GITHUB_APP_ID` | `""` | GitHub App ID for enterprise repository integrations |
| `GITHUB_PRIVATE_KEY` | `""` | GitHub App RSA Private Key in PEM format |
| `GITHUB_CLIENT_ID` | `""` | GitHub OAuth App Client ID |
| `GITHUB_CLIENT_SECRET` | `""` | GitHub OAuth App Client Secret |

---

## 5. External Dependency Status & Safe Fallbacks

SENTINEL-X is designed with zero-cascade dependency resilience:

| External Dependency | Status When Unconfigured | Fallback Behavior & Security Guard |
| :--- | :--- | :--- |
| **OpenRouter LLM API** (`OPENROUTER_API_KEY`) | Optional | Evaluates deterministic, rule-grounded vulnerability explanations and sample unified diffs. No outgoing HTTP requests are made. Untrusted inputs are never leaked. |
| **GitHub App / OAuth** (`GITHUB_APP_ID`, `GITHUB_CLIENT_ID`) | Optional | Manual repository clone URLs and personal access tokens are supported. Webhook receivers validate HMAC signatures and fail-closed (401) on missing secrets. |
| **Docker Host Daemon** (`/var/run/docker.sock`) | Optional | If Docker is absent or locked down (e.g. unprivileged CI container), runtime provisioning records `BLOCKED` for dynamic testing, while all static scanners, SBOM generation, correlation, and reports continue and complete. |
| **Redis Broker** (`REDIS_URL`) | Optional | Automatic in-memory sliding window rate limiter fallback is engaged transparently with warning logs. |
