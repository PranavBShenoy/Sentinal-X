"""Unit tests for the monitoring and alerting service."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.monitoring_service import MonitoringService

client = TestClient(app)


def test_monitoring_check_database_success():
    service = MonitoringService()
    mock_db = MagicMock()
    mock_engine = MagicMock()
    mock_db.get_bind.return_value = mock_engine

    res = service.check_database(mock_db)
    assert res["connected"] is True
    assert isinstance(res["latency_ms"], float)
    assert res["error"] is None


def test_monitoring_check_database_failure():
    service = MonitoringService()
    mock_db = MagicMock()
    mock_db.execute.side_effect = RuntimeError("Database connection terminated")

    res = service.check_database(mock_db)
    assert res["connected"] is False
    assert res["latency_ms"] is None
    assert "Database connection terminated" in res["error"]


def test_monitoring_check_redis_success():
    service = MonitoringService()
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    mock_redis.llen.side_effect = lambda q: 3 if q == "sentinelx" else 1
    mock_redis.info.return_value = {"used_memory_human": "45.2M"}

    with patch("redis.from_url", return_value=mock_redis):
        res = service.check_redis()
        assert res["connected"] is True
        assert isinstance(res["latency_ms"], float)
        assert res["queues"]["sentinelx"] == 3
        assert res["queues"]["celery"] == 1
        assert res["queues"]["default"] == 1
        assert res["queues"]["total_pending"] == 5
        assert res["used_memory"] == "45.2M"


def test_monitoring_check_workspace_storage(tmp_path):
    service = MonitoringService()
    service.settings.ASSESSMENT_WORKSPACE_BASE = str(tmp_path)

    res = service.check_workspace_storage()
    assert res["path"] == str(tmp_path)
    assert res["total_gb"] > 0
    assert res["free_gb"] > 0
    assert isinstance(res["used_percent"], float)
    assert res["low_space"] is False


def test_monitoring_telemetry_healthy_status():
    service = MonitoringService()
    with patch.object(service, "check_database", return_value={"connected": True, "latency_ms": 2.5, "error": None}), \
         patch.object(service, "check_redis", return_value={"connected": True, "latency_ms": 1.1, "queues": {"total_pending": 0}}), \
         patch.object(service, "check_workspace_storage", return_value={"low_space": False, "used_percent": 25.0}):
        data = service.get_system_telemetry()
        assert data["status"] == "healthy"
        assert len(data["alerts"]["degraded_reasons"]) == 0


def test_monitoring_telemetry_degraded_when_queue_spikes():
    service = MonitoringService()
    service.settings.ALERT_QUEUE_THRESHOLD = 10
    with patch.object(service, "check_database", return_value={"connected": True, "latency_ms": 2.5, "error": None}), \
         patch.object(service, "check_redis", return_value={"connected": True, "latency_ms": 1.1, "queues": {"total_pending": 45}}), \
         patch.object(service, "check_workspace_storage", return_value={"low_space": False, "used_percent": 25.0}):
        data = service.get_system_telemetry()
        assert data["status"] == "degraded"
        assert any("Celery queue backlog" in r for r in data["alerts"]["degraded_reasons"])


def test_monitoring_telemetry_unhealthy_when_db_down():
    service = MonitoringService()
    with patch.object(service, "check_database", return_value={"connected": False, "error": "Connection refused"}), \
         patch.object(service, "check_redis", return_value={"connected": True, "latency_ms": 1.0, "queues": {"total_pending": 0}}), \
         patch.object(service, "check_workspace_storage", return_value={"low_space": False}):
        data = service.get_system_telemetry()
        assert data["status"] == "unhealthy"


@pytest.mark.anyio
async def test_send_alert_webhook_no_url():
    service = MonitoringService()
    service.settings.ALERT_WEBHOOK_URL = None
    sent = await service.send_alert_webhook("test", "warning", "No url")
    assert sent is False


@pytest.mark.anyio
async def test_send_alert_webhook_success():
    service = MonitoringService()
    service.settings.ALERT_WEBHOOK_URL = "https://hooks.slack.com/services/test"

    mock_resp = MagicMock()
    mock_resp.is_success = True
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        sent = await service.send_alert_webhook("queue_spike", "warning", "Queue exceeded 50 tasks", {"queue": 52})
        assert sent is True
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["json"]["severity"] == "WARNING"
        assert call_kwargs["json"]["message"] == "Queue exceeded 50 tasks"


def test_api_health_telemetry_endpoint():
    resp = client.get("/api/v1/health/telemetry")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "database" in data
    assert "redis" in data
    assert "storage" in data
    assert "alerts" in data


def test_api_health_alert_test_endpoint():
    resp = client.post("/api/v1/health/alert-test")
    assert resp.status_code == 200
    data = resp.json()
    assert "delivered" in data
    assert "configured" in data
