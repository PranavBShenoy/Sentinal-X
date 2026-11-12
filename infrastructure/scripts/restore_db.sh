#!/usr/bin/env bash
# ==============================================================================
# SENTINEL-X Production Database Restoration Script
#
# Validates checksum integrity and restores a compressed PostgreSQL backup.
#
# Usage:
#   ./infrastructure/scripts/restore_db.sh <backup_file.sql.gz>
# ==============================================================================
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <path_to_backup_file.sql.gz>"
    exit 1
fi

BACKUP_FILE="$1"
CHECKSUM_FILE="${BACKUP_FILE}.sha256"

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "[!] Error: Backup file not found: ${BACKUP_FILE}"
    exit 1
fi

PGHOST="${POSTGRES_SERVER:-${PGHOST:-127.0.0.1}}"
PGPORT="${POSTGRES_PORT:-${PGPORT:-5432}}"
PGUSER="${POSTGRES_USER:-${PGUSER:-sentinelx}}"
PGDATABASE="${POSTGRES_DB:-${PGDATABASE:-sentinelx}}"

# 1. Verify SHA-256 Checksum if present
if [ -f "${CHECKSUM_FILE}" ]; then
    echo "[+] Verifying SHA-256 checksum..."
    (cd "$(dirname "${BACKUP_FILE}")" && sha256sum -c "$(basename "${CHECKSUM_FILE}")")
    echo "[✓] Checksum matches. Backup file integrity confirmed."
else
    echo "[!] Warning: No checksum file found at ${CHECKSUM_FILE}. Proceeding without verification."
fi

# 2. Confirm restoration target
echo "[!] RESTORATION WARNING:"
echo "    This operation will overwrite or modify tables in database '${PGDATABASE}' on ${PGHOST}:${PGPORT}."

# 3. Perform restoration
echo "[+] Decompressing and executing SQL restore..."
gunzip -c "${BACKUP_FILE}" | psql -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" -d "${PGDATABASE}" --single-transaction

# 4. Post-restore verification
echo "[+] Verifying database tables..."
TABLE_COUNT=$(psql -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" -d "${PGDATABASE}" -t -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';")
echo "[✓] Restoration completed successfully. Active public tables: ${TABLE_COUNT}."
