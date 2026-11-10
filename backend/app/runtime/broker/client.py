"""
Broker HTTP client used by the Runtime Orchestrator.

The Celery worker / orchestrator talks to the Runtime Broker over
authenticated HTTP. It never touches the Docker socket directly.

All calls fail closed: if the broker is unreachable or returns an error,
provisioning/cleanup reports failure rather than falling back to an
insecure direct-docker path.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import httpx

from app.core.config import get_settings

settings = get_settings()


class BrokerClient:
    """
    Client for the SENTINEL-X Runtime Broker.

    Authenticates with X-Broker-Key. Fail-closed on broker unavailability.
    """

    def __init__(
        self,
        broker_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.broker_url = (broker_url or settings.BROKER_URL).rstrip("/")
        self.api_key = api_key or settings.BROKER_API_KEY
        self.timeout_seconds = timeout_seconds
        self._headers = {"X-Broker-Key": self.api_key} if self.api_key else {}

    def is_available(self) -> bool:
        """Return True if the broker is reachable and reports healthy."""
        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.get(f"{self.broker_url}/v1/broker/health", headers=self._headers)
            return resp.status_code == 200 and resp.json().get("docker_available") is True
        except Exception:
            return False

    def _post(self, path: str, json: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.post(
                    f"{self.broker_url}{path}",
                    json=json,
                    headers=self._headers,
                )
            if resp.status_code >= 400:
                return False, {"error": resp.text[:300], "status_code": resp.status_code}
            return True, resp.json()
        except Exception as exc:
            return False, {"error": str(exc), "status_code": None}

    def _delete(self, path: str) -> Tuple[bool, Dict[str, Any]]:
        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.delete(f"{self.broker_url}{path}", headers=self._headers)
            if resp.status_code >= 400:
                return False, {"error": resp.text[:300], "status_code": resp.status_code}
            return True, resp.json()
        except Exception as exc:
            return False, {"error": str(exc), "status_code": None}

    # ------------------------------------------------------------------
    # Operations used by RuntimeOrchestrator
    # ------------------------------------------------------------------

    def build_image(
        self,
        workspace_path: str,
        image_tag: str,
        network_mode: str = "none",
    ) -> Tuple[bool, str]:
        """Build an image via the broker. Returns (ok, log_or_error)."""
        ok, data = self._post(
            "/v1/broker/build",
            {
                "workspace_path": workspace_path,
                "image_tag": image_tag,
                "network_mode": network_mode,
            },
        )
        if not ok:
            return False, data.get("error", "build request failed")
        return True, data.get("message", "built")

    def create_network(self, network_name: str, internal: bool = True) -> Tuple[bool, str]:
        """Create an isolated internal network via the broker."""
        ok, data = self._post(
            "/v1/broker/network/create",
            {"network_name": network_name, "internal": internal},
        )
        if not ok:
            return False, data.get("error", "network create failed")
        return True, data.get("message", "network created")

    def run_container(
        self,
        container_name: str,
        image_tag: str,
        network_name: str,
        app_port: int,
        host_port: int,
    ) -> Tuple[bool, Optional[int], str]:
        """
        Run a hardened container via the broker.

        Returns (ok, host_port, log_or_error). host_port is None on failure.
        """
        ok, data = self._post(
            "/v1/broker/container/run",
            {
                "container_name": container_name,
                "image_tag": image_tag,
                "network_name": network_name,
                "app_port": app_port,
                "host_port": host_port,
            },
        )
        if not ok:
            return False, None, data.get("error", "container run failed")
        return True, data.get("host_port"), data.get("message", "running")

    def get_logs(self, container_name: str) -> str:
        """Get redacted container logs (best effort; returns empty on failure)."""
        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.get(
                    f"{self.broker_url}/v1/broker/container/logs/{container_name}",
                    headers=self._headers,
                )
            if resp.status_code == 200:
                return resp.json().get("logs", "")
        except Exception:
            pass
        return ""

    def stop_container(self, container_name: str) -> Tuple[bool, str]:
        ok, data = self._post("/v1/broker/container/stop", {"container_name": container_name})
        return ok, data.get("message", "")

    def cleanup(
        self,
        container_name: str,
        network_name: str,
        image_tag: str,
    ) -> Dict[str, Any]:
        """
        Ordered teardown via the broker: container -> network -> image.

        Returns a dict summarizing results per step.
        """
        ok, data = self._post(
            "/v1/broker/cleanup",
            {
                "container_name": container_name,
                "network_name": network_name,
                "image_tag": image_tag,
            },
        )
        if not ok:
            return {"ok": False, "error": data.get("error", "cleanup failed")}
        return data
