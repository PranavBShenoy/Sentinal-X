# SENTINEL-X Operations & Deployment Guide

## 1. Prerequisites

- Linux server (Ubuntu 22.04 LTS or 24.04 LTS recommended)
- Docker Engine 24.0+ and Docker Compose v2+
- Python 3.11+ (if running bare metal)
- Node.js 20+ (for building frontend)
- Minimum Hardware: 4 vCPUs, 8 GB RAM, 50 GB SSD

---

## 2. Production Deployment via Docker Compose

### Step 1: Environment Configuration
Create a production `.env` file at the root:
```bash
ENVIRONMENT=production
DATABASE_URL=postgresql://sentinelx:STRONG_RANDOM_PASSWORD@postgres:5432/sentinelx
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/1

# Security Keys (Generate with `openssl rand -hex 32`)
JWT_SECRET_KEY=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
ENCRYPTION_KEY=dGhpcy1pcy1hLTMyLWJ5dGUtc2VjcmV0LWtleS0xMjM0NTY=

# AI Provider (Optional)
LLM_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-v1-your-key-here
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet

# CORS Settings
CORS_ORIGINS=["https://security.yourcompany.com"]
```

### Step 2: Initialize Database
```bash
docker compose run --rm api alembic upgrade head
```

### Step 3: Launch Services
```bash
docker compose up -d
```

### Step 4: Health Check Verification
```bash
curl -f http://localhost:8000/health
# Returns: {"status":"healthy","database":"connected","version":"1.0.0"}
```

---

## 3. Scaling Workers

To scale the execution worker fleet to handle concurrent assessments:
```bash
docker compose up -d --scale worker=4
```
Each worker pulls from the shared Redis `sentinelx` queue and processes tasks with isolated workspace directories.
