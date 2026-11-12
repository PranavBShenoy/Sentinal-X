"""
Docker command executor for the Runtime Broker.

The broker shells out to the Docker CLI (consistent with the existing
orchestrator) but only after policy validation. All commands run with
timeouts and secret redaction.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, Optional, Tuple

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.secret_redactor import redact
from app.core.subprocess_utils import run_command

logger = get_logger(__name__)
settings = get_settings()


class DockerExecutor:
    """
    Executes Docker CLI operations on behalf of the broker.

    The broker owns the Docker socket. This executor performs only the
    narrow set of operations SENTINEL-X requires, each with timeouts.
    """

    def __init__(
        self,
        timeout_build: int = 180,
        timeout_run: int = 20,
        timeout_network: int = 10,
        timeout_cleanup: int = 15,
        max_concurrent_builds: int = 2,
    ) -> None:
        self.timeout_build = timeout_build
        self.timeout_run = timeout_run
        self.timeout_network = timeout_network
        self.timeout_cleanup = timeout_cleanup
        # F-4: bound concurrent builds to prevent resource exhaustion.
        self._build_semaphore = threading.Semaphore(
            max_concurrent_builds or settings.BROKER_MAX_CONCURRENT_BUILDS
        )

    def is_available(self) -> Tuple[bool, str]:
        """Return (available, message) for the Docker daemon."""
        res = run_command(
            ["docker", "info"],
            timeout_seconds=5,
            tool_name="docker-info",
        )
        return res.succeeded, redact(res.stdout + "\n" + res.stderr)

    def build_image(
        self,
        workspace_path: str,
        image_tag: str,
        dockerfile_path: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Build an image using hardened build args (never --network=host).

        F-4: Acquires a bounded semaphore so that concurrent build requests
        cannot exhaust broker or host resources. Callers block until a build
        slot becomes available.
        """
        from app.runtime.broker.policy import build_docker_build_args

        acquired = self._build_semaphore.acquire(timeout=self.timeout_build)
        if not acquired:
            return False, (
                f"Build concurrency limit reached "
                f"({settings.BROKER_MAX_CONCURRENT_BUILDS} max concurrent builds); try again later."
            )
        try:
            args = build_docker_build_args(workspace_path, image_tag, dockerfile_path)
            res = run_command(
                args,
                timeout_seconds=self.timeout_build,
                tool_name="docker-build",
                cwd=workspace_path,
            )
            return res.succeeded, redact(res.stdout + "\n" + res.stderr)
        finally:
            self._build_semaphore.release()

    def create_network(self, network_name: str, internal: bool = True) -> Tuple[bool, str]:
        """Create a dedicated network (internal by default)."""
        args = ["docker", "network", "create"]
        if internal:
            args.append("--internal")
        args.append(network_name)
        res = run_command(
            args,
            timeout_seconds=self.timeout_network,
            tool_name="docker-network-create",
        )
        return res.succeeded, redact(res.stdout + "\n" + res.stderr)

    def run_container(
        self,
        container_name: str,
        image_tag: str,
        network_name: str,
        app_port: int,
        host_port: int,
    ) -> Tuple[bool, Optional[int], str]:
        """
        Run a hardened container. Returns (ok, host_port, logs).

        All security parameters are enforced by the broker policy; the
        caller cannot influence them.
        """
        from app.runtime.broker.policy import build_docker_run_args

        # Stale-container cleanup with the same name first.
        run_command(
            ["docker", "rm", "-f", container_name],
            timeout_seconds=self.timeout_network,
            tool_name="docker-rm-stale",
        )
        # Stale-network cleanup with the same name first.
        run_command(
            ["docker", "network", "rm", network_name],
            timeout_seconds=self.timeout_network,
            tool_name="docker-net-rm-stale",
        )

        net_ok, net_log = self.create_network(network_name, internal=True)
        if not net_ok:
            return False, None, f"Failed to create isolated internal network: {net_log[:300]}"

        args = build_docker_run_args(container_name, image_tag, network_name, app_port, host_port)
        res = run_command(
            args,
            timeout_seconds=self.timeout_run,
            tool_name="docker-run",
        )
        safe_output = redact(res.stdout + "\n" + res.stderr)
        if not res.succeeded:
            return False, None, safe_output

        return True, host_port, safe_output

    def get_logs(self, container_name: str) -> str:
        """Retrieve redacted container logs."""
        res = run_command(
            ["docker", "logs", "--tail=100", container_name],
            timeout_seconds=self.timeout_cleanup,
            tool_name="docker-logs",
        )
        return redact(res.stdout + "\n" + res.stderr)

    def stop_container(self, container_name: str) -> Tuple[bool, str]:
        res = run_command(
            ["docker", "stop", container_name],
            timeout_seconds=self.timeout_cleanup,
            tool_name="docker-stop",
        )
        return res.succeeded, redact(res.stdout + "\n" + res.stderr)

    def remove_container(self, container_name: str) -> Tuple[bool, str]:
        res = run_command(
            ["docker", "rm", "-f", container_name],
            timeout_seconds=self.timeout_cleanup,
            tool_name="docker-rm",
        )
        return res.succeeded, redact(res.stdout + "\n" + res.stderr)

    def remove_network(self, network_name: str) -> Tuple[bool, str]:
        res = run_command(
            ["docker", "network", "rm", network_name],
            timeout_seconds=self.timeout_network,
            tool_name="docker-network-rm",
        )
        return res.succeeded, redact(res.stdout + "\n" + res.stderr)

    def remove_image(self, image_tag: str) -> Tuple[bool, str]:
        res = run_command(
            ["docker", "rmi", image_tag],
            timeout_seconds=self.timeout_cleanup,
            tool_name="docker-rmi",
        )
        return res.succeeded, redact(res.stdout + "\n" + res.stderr)

    def cleanup(
        self,
        container_name: str,
        network_name: str,
        image_tag: str,
    ) -> Dict[str, Any]:
        """
        Ordered teardown: container -> network -> image.

        Returns a dict summarizing each step's success. All steps are
        attempted even if earlier ones fail.
        """
        from app.runtime.broker.policy import build_cleanup_args

        commands = build_cleanup_args(container_name, network_name, image_tag)
        results: Dict[str, Any] = {}
        for step, args in commands.items():
            res = run_command(
                args,
                timeout_seconds=self.timeout_cleanup,
                tool_name=f"docker-{step}",
            )
            results[step] = {
                "ok": res.succeeded,
                "log": redact(res.stdout + "\n" + res.stderr)[:200],
            }
        return results
