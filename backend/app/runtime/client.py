"""
Runtime client abstraction for SENTINEL-X.

Defines the interface that any Docker execution backend must implement so the
Celery worker / FastAPI control plane never needs to touch a Docker socket
directly.

Implementations:
- RuntimeBrokerClient (app.runtime.broker.client.BrokerClient): talks to the
  existing policy-enforcing Runtime Broker over authenticated HTTP.
- MockRuntimeClient (app.runtime.mock_client.MockRuntimeClient): simulated
  responses for local development / testing ONLY. Never represents real
  Docker execution.

Design constraints:
- The control plane must not mount or directly access a host Docker socket.
- All implementations fail closed when the backend is unavailable.
- Simulated implementations must be clearly distinguishable from live Docker
  execution (every response carries ``simulated=True``).
"""

from __future__ import annotations

import abc
from typing import Any, Dict, Optional, Tuple


class RuntimeClient(abc.ABC):
    """Abstract interface for Docker execution backends.

    Concrete implementations perform the actual Docker operations (build,
    network create, container run, logs, stop, cleanup). The
    :class:`RuntimeOrchestrator` holds a :class:`RuntimeClient` and never
    invokes the Docker CLI or socket itself.
    """

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Return True if the backend is reachable and healthy."""

    @abc.abstractmethod
    def build_image(
        self,
        workspace_path: str,
        image_tag: str,
        network_mode: str = "none",
    ) -> Tuple[bool, str]:
        """Build an assessment image.

        Returns (ok, log_or_error).
        """

    @abc.abstractmethod
    def create_network(self, network_name: str, internal: bool = True) -> Tuple[bool, str]:
        """Create an isolated network.

        Returns (ok, log_or_error).
        """

    @abc.abstractmethod
    def run_container(
        self,
        container_name: str,
        image_tag: str,
        network_name: str,
        app_port: int,
        host_port: int,
    ) -> Tuple[bool, Optional[int], str]:
        """Run a hardened container.

        Returns (ok, host_port, log_or_error). host_port is None on failure.
        """

    @abc.abstractmethod
    def get_logs(self, container_name: str) -> str:
        """Retrieve container logs (best effort)."""

    @abc.abstractmethod
    def stop_container(self, container_name: str) -> Tuple[bool, str]:
        """Stop a running container.

        Returns (ok, message).
        """

    @abc.abstractmethod
    def cleanup(
        self,
        container_name: str,
        network_name: str,
        image_tag: str,
    ) -> Dict[str, Any]:
        """Ordered teardown: container -> network -> image.

        Returns a dict summarizing results per step.
        """
