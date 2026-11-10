"""
Simulated runtime client for local development and testing.

``MockRuntimeClient`` implements the :class:`RuntimeClient` interface by
returning deterministic, canned responses. It never contacts a Docker daemon
and never performs real container execution.

Every response carries ``simulated=True`` so that callers (and tests) can
distinguish simulated execution from live Docker execution. Simulated mode is
development/test-only: production must not select it.

Use cases:
- Local development on machines without a Docker daemon (e.g. an 8GB laptop).
- Unit tests that exercise the orchestrator's provisioning / cleanup /
  failure-handling paths without requiring Docker.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from app.core.config import get_settings
from app.runtime.client import RuntimeClient

settings = get_settings()


class MockRuntimeClient(RuntimeClient):
    """Simulated Docker execution backend.

    All methods return canned success/failure responses. The ``simulated``
    flag is embedded in every log/message so the response can never be
    mistaken for real Docker execution.
    """

    def __init__(
        self,
        *,
        fail_build: bool = False,
        fail_start: bool = False,
        fail_cleanup: bool = False,
        fail_availability: bool = False,
    ) -> None:
        """Create a mock client.

        Args:
            fail_build: If True, :meth:`build_image` returns failure.
            fail_start: If True, :meth:`run_container` returns failure.
            fail_cleanup: If True, :meth:`cleanup` reports failure for all
                steps.
            fail_availability: If True, :meth:`is_available` returns False.
        """
        self.fail_build = fail_build
        self.fail_start = fail_start
        self.fail_cleanup = fail_cleanup
        self.fail_availability = fail_availability
        self.calls: list[dict] = []

    # -- RuntimeClient interface -------------------------------------------

    def is_available(self) -> bool:
        """Return whether the simulated backend is 'reachable'."""
        return not self.fail_availability

    def build_image(
        self,
        workspace_path: str,
        image_tag: str,
        network_mode: str = "none",
    ) -> Tuple[bool, str]:
        """Simulate an image build.

        Never invokes Docker. Returns success unless ``fail_build`` is set.
        """
        self.calls.append(
            {
                "operation": "build_image",
                "workspace_path": workspace_path,
                "image_tag": image_tag,
                "network_mode": network_mode,
            }
        )
        if self.fail_build:
            return False, "[simulated] build failed: cannot connect to Docker daemon"
        return True, "[simulated] image built successfully (simulated execution, no Docker used)"

    def create_network(self, network_name: str, internal: bool = True) -> Tuple[bool, str]:
        """Simulate network creation."""
        self.calls.append(
            {
                "operation": "create_network",
                "network_name": network_name,
                "internal": internal,
            }
        )
        return True, f"[simulated] network {network_name} created (simulated execution, no Docker used)"

    def run_container(
        self,
        container_name: str,
        image_tag: str,
        network_name: str,
        app_port: int,
        host_port: int,
    ) -> Tuple[bool, Optional[int], str]:
        """Simulate starting a container.

        Returns a simulated host_port (never a real bound port).
        """
        self.calls.append(
            {
                "operation": "run_container",
                "container_name": container_name,
                "image_tag": image_tag,
                "network_name": network_name,
                "app_port": app_port,
                "host_port": host_port,
            }
        )
        if self.fail_start:
            return False, None, "[simulated] container start failed: runtime unavailable"
        simulated_port = 19000
        return (
            True,
            simulated_port,
            f"[simulated] container {container_name} started on "
            f"127.0.0.1:{simulated_port} (simulated execution, no Docker used)",
        )

    def get_logs(self, container_name: str) -> str:
        """Return simulated (redacted) logs."""
        return f"[simulated] logs for {container_name} (simulated execution, no Docker used)"

    def stop_container(self, container_name: str) -> Tuple[bool, str]:
        """Simulate stopping a container."""
        self.calls.append({"operation": "stop_container", "container_name": container_name})
        return True, f"[simulated] container {container_name} stopped"

    def cleanup(
        self,
        container_name: str,
        network_name: str,
        image_tag: str,
    ) -> Dict[str, Any]:
        """Simulate ordered teardown: container -> network -> image."""
        self.calls.append(
            {
                "operation": "cleanup",
                "container_name": container_name,
                "network_name": network_name,
                "image_tag": image_tag,
            }
        )
        step_ok = not self.fail_cleanup
        return {
            "container": {"ok": step_ok, "log": "[simulated] container removed"},
            "network": {"ok": step_ok, "log": "[simulated] network removed"},
            "image": {"ok": step_ok, "log": "[simulated] image removed"},
        }
