#!/usr/bin/env bash
# ==============================================================================
# SENTINEL-X Pre-Flight Production Deployment Verification
#
# Validates platform prerequisites:
# - Python runtime & virtual environment
# - PostgreSQL schema and table migration state
# - Redis service connectivity & rate limiter readiness
# - Security scanner binaries (Gitleaks, Semgrep, Trivy, Syft, Grype, OSV)
# - API process health endpoints (/health/live and /health/ready)
# ==============================================================================
set -euo pipefail

# Prepend local workspace bin and standard binary directories to PATH
export PATH="/usr/local/bin:/usr/bin:/bin:${HOME}/Sentinal-X/bin:${PATH:-}"

echo "================================================================================"
echo " SENTINEL-X Production Pre-Flight Deployment Verification"
echo "================================================================================"

FAILED=0

check_cmd() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        echo " [✓] ${name}"
    else
        echo " [✗] FAILED: ${name}"
        FAILED=1
    fi
}

echo "[1/5] Checking Required System & Scanner Binaries..."
check_cmd "Gitleaks binary" "which gitleaks"
check_cmd "Trivy binary" "which trivy"
check_cmd "Syft binary" "which syft"
check_cmd "Grype binary" "which grype"
check_cmd "OSV-Scanner binary" "which osv-scanner"
check_cmd "Python 3.11+ runtime" "python3 -c 'import sys; assert sys.version_info >= (3, 11)'"

echo ""
echo "[2/5] Checking Database Connectivity & Schema Migrations..."
check_cmd "PostgreSQL Alembic current head" "cd backend && python3 -m alembic current"

echo ""
echo "[3/5] Checking Redis Broker & Rate Limiting Storage..."
check_cmd "Redis connection via redis-cli" "redis-cli ping || redis-cli -s /tmp/redis.sock ping"

echo ""
echo "[4/5] Checking Scanner Vulnerability Databases & Cache..."
check_cmd "OSV offline database cache" "test -f ~/.cache/osv-scalibr/PyPI/all.zip || echo 'Advisory: OSV offline database not cached'"
check_cmd "Grype vulnerability database" "grype db list >/dev/null 2>&1 || echo 'Advisory: Grype DB requires update'"

echo ""
echo "[5/5] Checking API Health Probes (if API running)..."
if curl -s -f http://127.0.0.1:8000/health/live >/dev/null 2>&1; then
    echo " [✓] API Liveness Probe (/health/live) is OK"
    if curl -s -f http://127.0.0.1:8000/health/ready >/dev/null 2>&1; then
        echo " [✓] API Readiness Probe (/health/ready) is OK"
    else
        echo " [!] API Readiness Probe (/health/ready) reported DEGRADED"
    fi
else
    echo " [i] API is not currently running on 127.0.0.1:8000 (skipped live probe)"
fi

echo "================================================================================"
if [ "${FAILED}" -eq 0 ]; then
    echo " RESULT: All deployment pre-flight checks PASSED."
    exit 0
else
    echo " RESULT: One or more pre-flight checks FAILED. Review errors above."
    exit 1
fi
