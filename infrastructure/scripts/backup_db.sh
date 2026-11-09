#!/usr/bin/env bash
# ==============================================================================
# SENTINEL-X Production Database Automated Backup Script
#
# Generates timestamped, compressed PostgreSQL database dumps with SHA-256 checksums
# and automatic retention rotation.
#
# Usage:
#   ./infrastructure/scripts/backup_db.sh [backup_dir]
# ==============================================================================
set -euo pipefail

BACKUP_DIR="${1:-${BACKUP_DIR:-/var/backups/sentinelx}}"
PGHOST="${POSTGRES_SERVER:-${PGHOST:-127.0.0.1}}"
PGPORT="${POSTGRES_PORT:-${PGPORT:-5432}}"
PGUSER="${POSTGRES_USER:-${PGUSER:-sentinelx}}"
PGDATABASE="${POSTGRES_DB:-${PGDATABASE:-sentinelx}}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"

TIMESTAMP="$(date -u +%Y%m%d_%H%M%SZ)"
BACKUP_FILE="${BACKUP_DIR}/sentinelx_backup_${TIMESTAMP}.sql.gz"
CHECKSUM_FILE="${BACKUP_FILE}.sha256"

mkdir -p "${BACKUP_DIR}"

echo "[+] Starting SENTINEL-X database backup..."
echo "    Target Database: ${PGDATABASE} on ${PGHOST}:${PGPORT} (user: ${PGUSER})"
echo "    Destination:     ${BACKUP_FILE}"

# Perform atomic pg_dump piped through gzip
pg_dump -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" -d "${PGDATABASE}" \
    --no-owner --no-privileges --clean --if-exists | gzip -9 > "${BACKUP_FILE}"

# Compute SHA-256 integrity checksum
sha256sum "${BACKUP_FILE}" > "${CHECKSUM_FILE}"

BACKUP_SIZE="$(du -h "${BACKUP_FILE}" | cut -f1)"
echo "[✓] Backup completed successfully (${BACKUP_SIZE})."
echo "[✓] Checksum written to ${CHECKSUM_FILE}."

# Enforce retention policy: purge backups older than RETENTION_DAYS
echo "[+] Rotating backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -name "sentinelx_backup_*.sql.gz*" -mtime +"${RETENTION_DAYS}" -delete || true
echo "[✓] Backup lifecycle complete."
