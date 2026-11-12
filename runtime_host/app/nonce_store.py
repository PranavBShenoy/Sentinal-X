"""
Durable nonce store for Runtime Host replay prevention.

Uses SQLite on the Runtime Host VM so that mutation-token replay protection
survives service restarts. One-time nonce consumption is enforced atomically
via a UNIQUE constraint and a transaction.
"""

from __future__ import annotations

import sqlite3
import threading
import time

NONCE_TTL_SECONDS = 300  # 5 minutes


class NonceStore:
    """Thread-safe durable nonce store with atomic one-time consumption."""

    def __init__(self, db_path: str | None = None) -> None:
        import os

        self.db_path = db_path or os.environ.get(
            "SENTINELX_NONCE_STORE_PATH",
            os.path.expanduser("~/.local/share/sentinelx/runtime_host/nonces.db"),
        )
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create the nonces table if it doesn't exist."""
        import os

        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS nonces (
                    jti TEXT PRIMARY KEY,
                    consumed_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_nonces_consumed_at "
                "ON nonces(consumed_at)"
            )
            conn.commit()

    def consume(self, jti: str, ttl_seconds: int = NONCE_TTL_SECONDS) -> bool:
        """Atomically consume a nonce.

        Returns True if the nonce was fresh and is now consumed.
        Returns False if the nonce was already consumed (replay).
        """
        now = time.time()
        with self._lock, self._get_conn() as conn:
            # Atomic insert: fails if jti already exists (replay)
            try:
                conn.execute(
                    "INSERT INTO nonces (jti, consumed_at) VALUES (?, ?)",
                    (jti, now),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                return False  # Already consumed -> replay
        return True

    def cleanup_expired(self, ttl_seconds: int = NONCE_TTL_SECONDS) -> int:
        """Remove expired nonces. Returns number of rows deleted."""
        cutoff = time.time() - ttl_seconds
        with self._lock, self._get_conn() as conn:
            cursor = conn.execute(
                "DELETE FROM nonces WHERE consumed_at < ?", (cutoff,)
            )
            conn.commit()
            return cursor.rowcount

    def is_consumed(self, jti: str) -> bool:
        """Check whether a nonce has already been consumed."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM nonces WHERE jti = ?", (jti,)
            ).fetchone()
        return row is not None
