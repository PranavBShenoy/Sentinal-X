"""
System health, latency, queue, and resource monitoring service for SENTINEL-X.

Provides telemetry across:
- Database connection, ping latency, and connection pool state.
- Redis connection, latency, and Celery queue depth.
- Workspace disk storage capacity.
- Automated webhook alerting hook for operational degradation.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import db_session
from app.core.logging import get_logger

logger = get_logger(__name__)


class MonitoringService:
    def __init__(self) -> None:
        self.settings = get_settings()

    def check_database(self, db: Optional[Session] = None) -> Dict[str, Any]:
        """Check PostgreSQL database connectivity, latency, and pool statistics."""
        t0 = time.perf_counter()
        connected = False
        latency_ms = None
        error = None
        pool_stats: Dict[str, Any] = {}

        try:
            if db:
                db.execute(text("SELECT 1"))
                engine = db.get_bind()
            else:
                with db_session() as session:
                    session.execute(text("SELECT 1"))
                    engine = session.get_bind()
            t1 = time.perf_counter()
            connected = True
            latency_ms = round((t1 - t0) * 1000, 2)

            # Inspect connection pool if available
            pool = getattr(engine, "pool", None)
            if pool:
                pool_stats = {
                    "size": getattr(pool, "size", lambda: None)(),
                    "checkedin": getattr(pool, "checkedin", lambda: None)(),
                    "checkedout": getattr(pool, "checkedout", lambda: None)(),
                    "overflow": getattr(pool, "overflow", lambda: None)(),
                }
        except Exception as exc:
            error = str(exc)
            logger.warning("Database health check failed", error=error)

        return {
            "connected": connected,
            "latency_ms": latency_ms,
            "error": error,
            "pool": pool_stats,
        }

    def check_redis(self) -> Dict[str, Any]:
        """Check Redis connectivity, latency, and queue backlog."""
        t0 = time.perf_counter()
        connected = False
        latency_ms = None
        error = None
        queues: Dict[str, int] = {}
        memory_human: Optional[str] = None

        try:
            import redis
            r = redis.from_url(self.settings.REDIS_URL, socket_timeout=3, decode_responses=True)
            if r.ping():
                t1 = time.perf_counter()
                connected = True
                latency_ms = round((t1 - t0) * 1000, 2)

                # Query Celery task queues
                for q in ("sentinelx", "celery", "default"):
                    try:
                        queues[q] = r.llen(q)
                    except Exception:
                        pass
                queues["total_pending"] = sum(queues.values())

                try:
                    info = r.info("memory")
                    memory_human = info.get("used_memory_human")
                except Exception:
                    pass
        except Exception as exc:
            error = str(exc)
            logger.warning("Redis health check failed", error=error)

        return {
            "connected": connected,
            "latency_ms": latency_ms,
            "error": error,
            "used_memory": memory_human,
            "queues": queues,
        }

    def check_workspace_storage(self) -> Dict[str, Any]:
        """Check filesystem capacity on the assessment workspace base directory."""
        path = self.settings.ASSESSMENT_WORKSPACE_BASE or tempfile.gettempdir()
        try:
            if not os.path.exists(path):
                os.makedirs(path, exist_ok=True)
            total, used, free = shutil.disk_usage(path)
            total_gb = round(total / (1024 ** 3), 2)
            used_gb = round(used / (1024 ** 3), 2)
            free_gb = round(free / (1024 ** 3), 2)
            used_percent = round((used / total) * 100, 1)
            return {
                "path": path,
                "total_gb": total_gb,
                "used_gb": used_gb,
                "free_gb": free_gb,
                "used_percent": used_percent,
                "low_space": used_percent >= self.settings.ALERT_DISK_THRESHOLD_PERCENT,
            }
        except Exception as exc:
            logger.warning("Storage health check failed", error=str(exc))
            return {"path": path, "error": str(exc), "low_space": False}

    def get_system_telemetry(self, db: Optional[Session] = None) -> Dict[str, Any]:
        """Collect aggregated telemetry across all infrastructure dependencies."""
        db_res = self.check_database(db)
        redis_res = self.check_redis()
        storage_res = self.check_workspace_storage()

        degraded_reasons: List[str] = []

        # Determine status
        if not db_res["connected"]:
            status = "unhealthy"
            degraded_reasons.append(f"Database disconnected: {db_res['error']}")
        elif not redis_res["connected"]:
            status = "unhealthy"
            degraded_reasons.append(f"Redis disconnected: {redis_res['error']}")
        else:
            status = "healthy"

            # Check latency thresholds
            if db_res.get("latency_ms") and db_res["latency_ms"] > self.settings.ALERT_LATENCY_THRESHOLD_MS:
                status = "degraded"
                degraded_reasons.append(
                    f"High database latency: {db_res['latency_ms']}ms > {self.settings.ALERT_LATENCY_THRESHOLD_MS}ms"
                )

            if redis_res.get("latency_ms") and redis_res["latency_ms"] > self.settings.ALERT_LATENCY_THRESHOLD_MS:
                status = "degraded"
                degraded_reasons.append(
                    f"High Redis latency: {redis_res['latency_ms']}ms > {self.settings.ALERT_LATENCY_THRESHOLD_MS}ms"
                )

            # Check queue threshold
            pending = redis_res.get("queues", {}).get("total_pending", 0)
            if pending > self.settings.ALERT_QUEUE_THRESHOLD:
                status = "degraded"
                degraded_reasons.append(
                    f"Celery queue backlog: {pending} tasks > threshold {self.settings.ALERT_QUEUE_THRESHOLD}"
                )

            # Check storage threshold
            if storage_res.get("low_space"):
                status = "degraded"
                degraded_reasons.append(
                    f"Low workspace storage space: {storage_res.get('used_percent')}% used"
                )

        return {
            "status": status,
            "environment": self.settings.APP_ENV,
            "timestamp": time.time(),
            "database": db_res,
            "redis": redis_res,
            "storage": storage_res,
            "alerts": {
                "webhook_configured": bool(self.settings.ALERT_WEBHOOK_URL),
                "degraded_reasons": degraded_reasons,
            },
        }

    async def send_alert_webhook(
        self,
        event_type: str,
        severity: str,
        message: str,
        metrics: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Send an operational alert to configured webhook destination (Slack/Discord/PagerDuty)."""
        webhook_url = self.settings.ALERT_WEBHOOK_URL
        if not webhook_url:
            logger.info("Alert webhook not configured; skipping notification", event=event_type, severity=severity)
            return False

        payload = {
            "service": "SENTINEL-X",
            "environment": self.settings.APP_ENV,
            "event_type": event_type,
            "severity": severity.upper(),
            "message": message,
            "metrics": metrics or {},
            "timestamp": time.time(),
        }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(webhook_url, json=payload)
                if resp.is_success:
                    logger.info("Alert webhook delivered successfully", event=event_type, status=resp.status_code)
                    return True
                logger.warning("Alert webhook rejected by destination", status=resp.status_code, body=resp.text[:200])
                return False
        except Exception as exc:
            logger.error("Failed to deliver alert webhook", error=str(exc))
            return False


monitoring_service = MonitoringService()
