"""
Docker Runtime Orchestrator for Assessed Applications.

Provisions, isolates, health-checks, and cleans up temporary Docker environments
for supported applications (FastAPI, Flask, Express, Next.js, React).

SECURITY ARCHITECTURE (INFRA-01):
- This orchestrator does NOT touch the Docker socket directly.
- All Docker operations delegate to the SENTINEL-X Runtime Broker
  (app.runtime.broker), which holds the socket and enforces a strict
  security policy on every request.
- The broker enforces: cap_drop=ALL, no-new-privileges, read-only rootfs,
  non-root execution, CPU/memory/pids limits, 127.0.0.1-only port binding,
  --internal network, no host mounts, no host networking, no exec.
- If the broker is unavailable, provisioning fails closed (no insecure
  direct-docker fallback).

Public interface is preserved: provision(), cleanup(), is_docker_available().
Internal Docker helpers delegate to the broker.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.core.config import get_settings
from app.core.database import db_session
from app.core.logging import get_logger
from app.models import RuntimeEnvironment, RuntimeStatus
from app.runtime.broker.client import BrokerClient
from app.runtime.detection.detector import ProjectDetector, ProjectProfile

logger = get_logger(__name__)
settings = get_settings()


class RuntimeOrchestrator:
    """Manages the lifecycle of isolated Docker runtimes for security assessments.

    All Docker operations are delegated to the Runtime Broker. The orchestrator
    retains ownership of the provisioning workflow, state tracking, and health
    checking, but never invokes the Docker CLI or socket directly.
    """

    def __init__(self) -> None:
        self.detector = ProjectDetector()
        self.broker = BrokerClient()

    def is_docker_available(self) -> bool:
        """Return True if the Runtime Broker is reachable and Docker is available."""
        return self.broker.is_available()

    def provision(self, assessment_id: str, workspace_path: str) -> Dict[str, Any]:
        """
        Main entry point: detect project, build container, start, and run health check.

        All Docker operations delegate to the broker. Always records outcome in
        RuntimeEnvironment model. Returns dictionary with runtime status and
        reachable target URL (if running).

        Fails closed when the broker is unavailable.
        """
        logger.info("Starting runtime provisioning", assessment_id=assessment_id)

        # 1. Initialize or get RuntimeEnvironment in DB
        self._ensure_runtime_record(assessment_id)

        # 2. Check broker / Docker availability
        if not self.is_docker_available():
            msg = "Runtime broker is not reachable or Docker is unavailable."
            logger.warning("Docker broker unavailable for runtime provisioning", assessment_id=assessment_id)
            self._update_runtime_status(
                assessment_id=assessment_id,
                status=RuntimeStatus.FAILED,
                failure_stage="BROKER_CHECK",
                failure_reason=msg,
            )
            return {"status": RuntimeStatus.FAILED.value, "target_url": None, "error": msg}

        # 3. Detect project structure
        profile = self.detector.detect(workspace_path)
        if profile.project_type == "unknown":
            msg = (
                "Unsupported project type or missing entry point. "
                "Supported: FastAPI, Flask, Node.js/Express, Next.js, React."
            )
            logger.info("Project type unsupported for auto-runtime", assessment_id=assessment_id)
            self._update_runtime_status(
                assessment_id=assessment_id,
                status=RuntimeStatus.UNSUPPORTED,
                failure_stage="DETECTION",
                failure_reason=msg,
                adapter_type="unknown",
            )
            return {"status": RuntimeStatus.UNSUPPORTED.value, "target_url": None, "error": msg}

        # 4. Check for required env vars
        if profile.required_env_vars:
            missing_vars = [v for v in profile.required_env_vars if v not in os.environ]
            if missing_vars:
                logger.info(
                    "Detected environment variable dependencies",
                    missing=missing_vars,
                    assessment_id=assessment_id,
                )

        self._update_runtime_status(
            assessment_id=assessment_id,
            status=RuntimeStatus.BUILDING,
            adapter_type=profile.project_type,
        )

        image_tag = f"sentinelx-app-{assessment_id.lower()[:12]}"
        container_name = f"sentinelx-cont-{assessment_id.lower()[:12]}"
        network_name = f"sentinelx-net-{assessment_id.lower()[:12]}"

        # 5. Build Docker Image (via broker)
        try:
            build_ok, build_log = self._build_image(workspace_path, profile, image_tag)
        except Exception as exc:
            logger.exception("Broker build call raised an exception", assessment_id=assessment_id, error=str(exc))
            self._cleanup_resources(container_name, network_name, image_tag)
            self._update_runtime_status(
                assessment_id=assessment_id,
                status=RuntimeStatus.FAILED,
                failure_stage="IMAGE_BUILD",
                failure_reason=f"Broker build call raised an exception: {exc}",
            )
            return {"status": RuntimeStatus.FAILED.value, "target_url": None, "error": "Build failed"}

        if not build_ok:
            self._update_runtime_status(
                assessment_id=assessment_id,
                status=RuntimeStatus.FAILED,
                failure_stage="IMAGE_BUILD",
                failure_reason=f"Docker image build failed: {build_log[:300]}",
                safe_log_summary=build_log,
            )
            # A failed build may leave a partial image behind; clean it up via broker.
            self._cleanup_resources(container_name, network_name, image_tag)
            return {"status": RuntimeStatus.FAILED.value, "target_url": None, "error": "Build failed"}

        # 6. Start Container with Security Constraints (via broker)
        self._update_runtime_status(assessment_id=assessment_id, status=RuntimeStatus.STARTING)

        app_port = profile.port or 8000
        host_port = self._find_available_port()

        try:
            start_ok, broker_host_port, start_log = self._start_container(
                container_name=container_name,
                network_name=network_name,
                image_tag=image_tag,
                app_port=app_port,
                host_port=host_port,
            )
        except Exception as exc:
            logger.exception("Broker container run raised an exception", assessment_id=assessment_id, error=str(exc))
            self._cleanup_resources(container_name, network_name, image_tag)
            self._update_runtime_status(
                assessment_id=assessment_id,
                status=RuntimeStatus.FAILED,
                failure_stage="CONTAINER_START",
                failure_reason=f"Broker container run raised an exception: {exc}",
            )
            return {"status": RuntimeStatus.FAILED.value, "target_url": None, "error": "Start failed"}

        if not start_ok or broker_host_port is None:
            self._update_runtime_status(
                assessment_id=assessment_id,
                status=RuntimeStatus.FAILED,
                failure_stage="CONTAINER_START",
                failure_reason=f"Failed to start container: {start_log[:300]}",
                safe_log_summary=start_log,
            )
            self._cleanup_resources(container_name, network_name, image_tag)
            return {"status": RuntimeStatus.FAILED.value, "target_url": None, "error": "Start failed"}

        # Use the port returned by the broker (bound to 127.0.0.1 only).
        host_port = broker_host_port
        target_url = f"http://127.0.0.1:{host_port}"

        # 7. Health Check (direct HTTP to the container's published loopback port)
        try:
            health_ok = self._health_check(target_url, timeout_seconds=30)
            logs = self._get_container_logs(container_name)
        except Exception as exc:
            logger.exception("Health check raised an exception", target_url=target_url, error=str(exc))
            self._cleanup_resources(container_name, network_name, image_tag)
            self._update_runtime_status(
                assessment_id=assessment_id,
                status=RuntimeStatus.FAILED,
                failure_stage="HEALTH_CHECK",
                failure_reason=f"Health check raised an exception: {exc}",
            )
            return {"status": RuntimeStatus.FAILED.value, "target_url": target_url, "error": "Health check failed"}

        if not health_ok:
            logger.warning("Health check failed on running container", target_url=target_url)
            self._update_runtime_status(
                assessment_id=assessment_id,
                status=RuntimeStatus.HEALTH_CHECK_FAILED,
                target_url=target_url,
                health_check_passed=False,
                failure_stage="HEALTH_CHECK",
                failure_reason="Application did not respond to HTTP health probe within 30 seconds.",
                safe_log_summary=logs,
                container_ids=[container_name],
            )
            # Always clean up the container, network, and image after a failed provisioning.
            self._cleanup_resources(container_name, network_name, image_tag)
            return {
                "status": RuntimeStatus.HEALTH_CHECK_FAILED.value,
                "target_url": target_url,
                "health_check_passed": False,
            }

        # 8. Success: Application is running and verified healthy
        self._update_runtime_status(
            assessment_id=assessment_id,
            status=RuntimeStatus.RUNNING,
            target_url=target_url,
            health_check_passed=True,
            safe_log_summary=logs,
            container_ids=[container_name],
            network_id=network_name,
        )

        logger.info("Runtime successfully provisioned", target_url=target_url, assessment_id=assessment_id)
        return {
            "status": RuntimeStatus.RUNNING.value,
            "target_url": target_url,
            "health_check_passed": True,
            "container_name": container_name,
        }

    def cleanup(self, assessment_id: str) -> None:
        """Stop and remove all containers and networks for an assessment (via broker)."""
        network_id = None
        with db_session() as db:
            env = (
                db.query(RuntimeEnvironment)
                .filter(RuntimeEnvironment.assessment_id == assessment_id)
                .first()
            )
            if env:
                network_id = env.network_id

        container_name = f"sentinelx-cont-{assessment_id.lower()[:12]}"
        image_tag = f"sentinelx-app-{assessment_id.lower()[:12]}"
        net_name = network_id or f"sentinelx-net-{assessment_id.lower()[:12]}"

        self._cleanup_resources(container_name, net_name, image_tag)

        self._update_runtime_status(
            assessment_id=assessment_id,
            status=RuntimeStatus.CLEANUP_DONE,
        )

    # ---------------------------------------------------------------------------
    # Docker helpers — delegate to the Runtime Broker
    # ---------------------------------------------------------------------------

    def _generate_dockerfile(self, profile: ProjectProfile) -> str:
        """Create a standard, secure Dockerfile with non-root user for supported frameworks."""
        pt = profile.project_type
        if pt in ("fastapi", "flask"):
            entry_module = "main:app"
            if profile.entry_point:
                module_name = Path(profile.entry_point).stem
                entry_module = f"{module_name}:app"
            return (
                "FROM python:3.11-slim-bookworm\n"
                "WORKDIR /app\n"
                "COPY . /app\n"
                "RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi\n"
                "RUN groupadd -r appuser && useradd -r -g appuser -u 10001 -s /bin/false appuser && chown -R appuser:appuser /app\n"
                "USER appuser\n"
                f"EXPOSE {profile.port}\n"
                f"CMD [\"python\", \"-m\", \"uvicorn\", \"{entry_module}\", \"--host\", \"0.0.0.0\", \"--port\", \"{profile.port}\"]\n"
            )
        elif pt in ("nodejs", "nextjs", "react"):
            return (
                "FROM node:20-slim\n"
                "WORKDIR /app\n"
                "COPY . /app\n"
                "RUN if [ -f package.json ]; then npm install --production --silent; fi\n"
                "USER node\n"
                f"EXPOSE {profile.port}\n"
                "CMD [\"npm\", \"start\"]\n"
            )
        else:
            return "FROM alpine:3.19\nCMD [\"echo\", \"unsupported\"]\n"

    def _build_image(
        self,
        workspace_path: str,
        profile: ProjectProfile,
        image_tag: str,
    ) -> Tuple[bool, str]:
        """
        Build an image via the broker.

        If the workspace has no Dockerfile, generate a secure one, build, then
        remove the generated file so the workspace is not polluted.
        """
        dockerfile_path = Path(workspace_path) / "Dockerfile"
        generated_dockerfile = False

        if not dockerfile_path.exists():
            generated_content = self._generate_dockerfile(profile)
            with open(dockerfile_path, "w", encoding="utf-8") as f:
                f.write(generated_content)
            generated_dockerfile = True

        try:
            build_ok, build_log = self.broker.build_image(
                workspace_path=workspace_path,
                image_tag=image_tag,
                network_mode=settings.BUILD_NETWORK_MODE,
            )
        finally:
            if generated_dockerfile and dockerfile_path.exists():
                try:
                    dockerfile_path.unlink()
                except Exception:
                    pass

        return build_ok, build_log

    def _start_container(
        self,
        container_name: str,
        network_name: str,
        image_tag: str,
        app_port: int,
        host_port: int,
    ) -> Tuple[bool, Optional[int], str]:
        """Start a hardened container via the broker (all security params enforced there)."""
        return self.broker.run_container(
            container_name=container_name,
            image_tag=image_tag,
            network_name=network_name,
            app_port=app_port,
            host_port=host_port,
        )

    def _health_check(self, target_url: str, timeout_seconds: int = 30) -> bool:
        """Poll the target application until it responds or timeout expires."""
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                with httpx.Client(timeout=2) as client:
                    resp = client.get(target_url)
                    # Any response code (even 404 or 401) indicates HTTP server is running
                    if resp.status_code > 0:
                        return True
            except Exception:
                time.sleep(1.5)
        return False

    def _get_container_logs(self, container_name: str) -> str:
        """Retrieve redacted container logs from the broker."""
        return self.broker.get_logs(container_name)

    def _cleanup_resources(self, container_name: str, network_name: str, image_tag: str) -> None:
        """Remove container, network, and intermediate build image via the broker."""
        self.broker.cleanup(container_name, network_name, image_tag)

    def _find_available_port(self) -> int:
        """Find an available local TCP port (used as a hint; broker may rebind)."""
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    # ---------------------------------------------------------------------------
    # Database State Helpers
    # ---------------------------------------------------------------------------

    def _ensure_runtime_record(self, assessment_id: str) -> None:
        with db_session() as db:
            env = db.query(RuntimeEnvironment).filter(RuntimeEnvironment.assessment_id == assessment_id).first()
            if not env:
                env = RuntimeEnvironment(
                    assessment_id=assessment_id,
                    status=RuntimeStatus.NOT_ATTEMPTED,
                    provisioning_started_at=datetime.now(timezone.utc),
                )
                db.add(env)

    def _update_runtime_status(
        self,
        assessment_id: str,
        status: RuntimeStatus,
        target_url: Optional[str] = None,
        health_check_passed: Optional[bool] = None,
        failure_stage: Optional[str] = None,
        failure_reason: Optional[str] = None,
        safe_log_summary: Optional[str] = None,
        adapter_type: Optional[str] = None,
        container_ids: Optional[List[str]] = None,
        network_id: Optional[str] = None,
    ) -> None:
        with db_session() as db:
            env = db.query(RuntimeEnvironment).filter(RuntimeEnvironment.assessment_id == assessment_id).first()
            if env:
                env.status = status
                if target_url:
                    env.target_url = target_url
                if health_check_passed is not None:
                    env.health_check_passed = health_check_passed
                if failure_stage:
                    env.failure_stage = failure_stage
                if failure_reason:
                    env.failure_reason = failure_reason
                if safe_log_summary:
                    env.safe_log_summary = safe_log_summary
                if adapter_type:
                    env.adapter_type = adapter_type
                if container_ids:
                    env.container_ids = container_ids
                if network_id:
                    env.network_id = network_id

                if status == RuntimeStatus.RUNNING:
                    env.running_since = datetime.now(timezone.utc)
                elif status in (RuntimeStatus.STOPPED, RuntimeStatus.CLEANUP_DONE):
                    env.stopped_at = datetime.now(timezone.utc)
                    env.cleanup_at = datetime.now(timezone.utc)
