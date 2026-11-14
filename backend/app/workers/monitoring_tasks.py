"""
Periodic and on-demand Celery worker tasks for infrastructure health monitoring and alerting.
"""
from __future__ import annotations

import asyncio
from app.core.logging import get_logger
from app.services.monitoring_service import monitoring_service
from app.workers.celery_app import celery_app

logger = get_logger(__name__)


@celery_app.task(name="app.workers.monitoring_tasks.check_system_health", bind=True, max_retries=1)
def check_system_health(self) -> dict:
    """Evaluate system telemetry and trigger webhook alerting if unhealthy or degraded."""
    logger.info("Executing Celery worker infrastructure telemetry probe")
    telemetry = monitoring_service.get_system_telemetry()

    if telemetry["status"] in ("unhealthy", "degraded"):
        reasons = "; ".join(telemetry["alerts"]["degraded_reasons"])
        logger.warning("System health alert condition detected", status=telemetry["status"], reasons=reasons)
        try:
            asyncio.run(
                monitoring_service.send_alert_webhook(
                    event_type="system_health_degraded",
                    severity="critical" if telemetry["status"] == "unhealthy" else "warning",
                    message=f"SENTINEL-X system status is {telemetry['status'].upper()}: {reasons}",
                    metrics=telemetry,
                )
            )
        except Exception as exc:
            logger.error("Failed to execute alert webhook from worker", error=str(exc))

    return telemetry
