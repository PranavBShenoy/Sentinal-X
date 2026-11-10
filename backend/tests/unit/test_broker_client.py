"""
Unit tests for the BrokerClient (orchestrator -> broker).

Verifies:
- is_available() parses broker health correctly
- build_image / run_container / cleanup delegate to broker
- Fail-closed: broker unreachable returns (False, error)
- Auth header sent on every request
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from app.runtime.broker.client import BrokerClient


def _fake_json(data: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = data
    resp.text = ""
    return resp


def test_broker_client_is_available_true():
    client = BrokerClient(broker_url="http://broker:8001", api_key="key-123")
    with patch("httpx.Client") as mock_client:
        instance = MagicMock()
        mock_client.return_value.__enter__.return_value = instance
        instance.get.return_value = _fake_json({"status": "healthy", "docker_available": True})
        assert client.is_available() is True
        # Auth header present
        args, kwargs = instance.get.call_args
        assert kwargs["headers"]["X-Broker-Key"] == "key-123"


def test_broker_client_is_available_false_when_docker_down():
    client = BrokerClient(broker_url="http://broker:8001", api_key="key-123")
    with patch("httpx.Client") as mock_client:
        instance = MagicMock()
        mock_client.return_value.__enter__.return_value = instance
        instance.get.return_value = _fake_json({"status": "degraded", "docker_available": False})
        assert client.is_available() is False


def test_broker_client_is_available_false_on_connection_error():
    client = BrokerClient(broker_url="http://broker:8001", api_key="key-123")
    with patch("httpx.Client") as mock_client:
        instance = MagicMock()
        mock_client.return_value.__enter__.return_value = instance
        instance.get.side_effect = httpx.ConnectError("broker down")
        assert client.is_available() is False


def test_broker_client_build_image_delegates():
    client = BrokerClient(broker_url="http://broker:8001", api_key="key-123")
    with patch("httpx.Client") as mock_client:
        instance = MagicMock()
        mock_client.return_value.__enter__.return_value = instance
        instance.post.return_value = _fake_json({"ok": True, "message": "built", "image_tag": "sentinelx-app-abc12345"})
        ok, log = client.build_image("/tmp/sentinelx/workspaces/a1", "sentinelx-app-abc12345")
        assert ok is True
        # Auth header present on post
        _, kwargs = instance.post.call_args
        assert kwargs["headers"]["X-Broker-Key"] == "key-123"
        assert kwargs["json"]["image_tag"] == "sentinelx-app-abc12345"


def test_broker_client_build_image_fail_closed_on_error():
    client = BrokerClient(broker_url="http://broker:8001", api_key="key-123")
    with patch("httpx.Client") as mock_client:
        instance = MagicMock()
        mock_client.return_value.__enter__.return_value = instance
        instance.post.return_value = _fake_json(
            {"ok": False, "message": "build failed", "log": "network error"}, status_code=400
        )
        ok, log = client.build_image("/tmp/sentinelx/workspaces/a1", "sentinelx-app-abc12345")
        assert ok is False


def test_broker_client_run_container_returns_host_port():
    client = BrokerClient(broker_url="http://broker:8001", api_key="key-123")
    with patch("httpx.Client") as mock_client:
        instance = MagicMock()
        mock_client.return_value.__enter__.return_value = instance
        instance.post.return_value = _fake_json(
            {
                "ok": True,
                "host_port": 12345,
                "target_url": "http://127.0.0.1:12345",
                "message": "running",
            }
        )
        ok, host_port, log = client.run_container(
            "sentinelx-cont-abc12345",
            "sentinelx-app-abc12345",
            "sentinelx-net-abc12345",
            8000,
            12345,
        )
        assert ok is True
        assert host_port == 12345


def test_broker_client_run_container_fail_closed_on_unreachable():
    client = BrokerClient(broker_url="http://broker:8001", api_key="key-123")
    with patch("httpx.Client") as mock_client:
        instance = MagicMock()
        mock_client.return_value.__enter__.return_value = instance
        instance.post.side_effect = httpx.ConnectError("broker unreachable")
        ok, host_port, log = client.run_container(
            "sentinelx-cont-abc12345",
            "sentinelx-app-abc12345",
            "sentinelx-net-abc12345",
            8000,
            12345,
        )
        assert ok is False
        assert host_port is None


def test_broker_client_cleanup_delegates():
    client = BrokerClient(broker_url="http://broker:8001", api_key="key-123")
    with patch("httpx.Client") as mock_client:
        instance = MagicMock()
        mock_client.return_value.__enter__.return_value = instance
        instance.post.return_value = _fake_json(
            {
                "ok": True,
                "steps": {
                    "container": {"ok": True},
                    "network": {"ok": True},
                    "image": {"ok": True},
                },
            }
        )
        result = client.cleanup(
            "sentinelx-cont-abc12345",
            "sentinelx-net-abc12345",
            "sentinelx-app-abc12345",
        )
        assert result["ok"] is True
