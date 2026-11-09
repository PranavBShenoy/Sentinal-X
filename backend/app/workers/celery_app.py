"""
Celery application configuration for SENTINEL-X.

Workers handle long-running assessment tasks asynchronously.
The API server never executes repository code or runs scanners directly.
"""
from __future__ import annotations

import os
from celery import Celery
from celery.utils.log import get_task_logger

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "sentinelx",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.workers.assessment_tasks",
    ],
)

celery_app.conf.update(
    # Serialization
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    # Reliability
    task_always_eager=settings.APP_ENV in ("test", "testing") or os.environ.get("CELERY_TASK_ALWAYS_EAGER", "false").lower() in ("true", "1"),
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,  # Fair distribution

    # Timeouts — individual scanner tasks have their own timeouts
    task_soft_time_limit=600,  # 10 minutes soft limit
    task_time_limit=720,       # 12 minutes hard kill

    # Retries
    task_max_retries=2,
    task_default_retry_delay=30,

    # Routing — single queue for now, expandable
    task_default_queue="sentinelx",
    task_routes={
        "app.workers.assessment_tasks.*": {"queue": "sentinelx"},
    },

    # Result expiry
    result_expires=86400,  # 24 hours

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Worker concurrency (also set via CLI --concurrency)
    worker_concurrency=settings.WORKER_CONCURRENCY,

    # Beat schedule (if scheduler is enabled)
    beat_schedule={
        "cleanup-expired-workspaces": {
            "task": "app.workers.assessment_tasks.cleanup_expired_workspaces",
            "schedule": 3600,  # Every hour
        },
    },
)

logger = get_task_logger(__name__)
