"""
Docker CLI executor for the Runtime Host.

Executes Docker commands on the Runtime Host VM with a fixed security policy.
The Runtime Host owns the Docker socket; the control plane never accesses it.

All container configurations are generated internally from the job request
and security policy. The control plane never supplies arbitrary Docker
parameters.
"""

from __future__ import annotations

import logging
import os
import subprocess
import shutil
import tarfile
from pathlib import Path

from .artifact import ArtifactError, download_artifact, extract_artifact_safely
from .config import load_advertised_target

from .policy import (
    DEFAULT_POLICY,
    ContainerSecurityPolicy,
)
from .schemas import (
    JobCancelResponse,
    JobLogsResponse,
    JobStatusResponse,
    JobSubmitResponse,
)

logger = logging.getLogger(__name__)


class DockerExecutor:
    """Executes Docker commands on the Runtime Host with fixed security policy."""

    def __init__(
        self,
        policy: ContainerSecurityPolicy = DEFAULT_POLICY,
        *,
        advertised_host: str | None = None,
        bind_ip: str | None = None,
    ) -> None:
        self.policy = policy
        configured_host, configured_bind_ip = load_advertised_target()
        self.advertised_host = advertised_host or configured_host
        self.bind_ip = bind_ip or configured_bind_ip

    def _run_docker(
        self, args: list[str], timeout_seconds: int = 60
    ) -> tuple[bool, str]:
        """Run a Docker CLI command and return (ok, output)."""
        try:
            result = subprocess.run(
                ["docker"] + args,
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout_seconds,
            )
            if result.returncode != 0:
                return False, result.stderr.strip() or result.stdout.strip()
            return True, result.stdout.strip()
        except subprocess.TimeoutExpired as exc:
            return False, f"Docker command timed out: {exc}"
        except FileNotFoundError:
            return False, "Docker CLI not found"
        except Exception as exc:  # noqa: BLE001
            return False, f"Docker command failed: {exc}"

    def _generate_dockerfile(self, app_port: int) -> str:
        """Generate a minimal secure Dockerfile for the workload.

        The Dockerfile is generated internally, never client-supplied.
        """
        return (
            "FROM python:3.11-slim-bookworm\n"
            "WORKDIR /app\n"
            "COPY . /app\n"
            "RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true\n"
            "RUN groupadd -r appuser && useradd -r -g appuser -u 10001 -s /bin/false appuser && chown -R appuser:appuser /app\n"
            "USER appuser\n"
            f"EXPOSE {app_port}\n"
            'CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", f"{app_port}"]\n'
        )

    def submit_build(
        self,
        *,
        job_id: str,
        assessment_id: str,
        artifact_tarball_path: str | None = None,
        artifact_url: str | None = None,
        artifact_sha256: str | None = None,
        image_tag: str,
        network_mode: str = "none",
    ) -> JobSubmitResponse:
        """Execute a build job: extract tarball, build image.

        Returns a JobSubmitResponse.
        """
        extract_dir = None
        try:
            if artifact_url:
                if not artifact_sha256:
                    raise ArtifactError("Artifact SHA-256 capability claim is required")
                artifact_bytes = download_artifact(artifact_url, artifact_sha256)
            elif artifact_tarball_path:
                artifact_bytes = Path(artifact_tarball_path).read_bytes()
            else:
                raise ArtifactError("A remote artifact URL is required")
            extract_dir = extract_artifact_safely(artifact_bytes)

            # Generate Dockerfile
            dockerfile_path = os.path.join(extract_dir, "Dockerfile")
            with open(dockerfile_path, "w") as f:
                f.write(self._generate_dockerfile(app_port=8000))

            # Build image with --network=none
            ok, output = self._run_docker(
                [
                    "build",
                    "-t",
                    image_tag,
                    "-f",
                    dockerfile_path,
                    "--network",
                    network_mode,
                    extract_dir,
                ],
                timeout_seconds=self.policy.build_timeout_seconds,
            )
            if not ok:
                return JobSubmitResponse(
                    job_id=job_id,
                    status="FAILED",
                    message=f"Build failed: {output[:300]}",
                )

            return JobSubmitResponse(
                job_id=job_id,
                status="BUILDING",
                message="Build started successfully",
            )
        except (ArtifactError, OSError, tarfile.TarError) as exc:
            return JobSubmitResponse(
                job_id=job_id,
                status="FAILED",
                message=f"Artifact rejected: {str(exc)[:300]}",
            )
        finally:
            if extract_dir:
                shutil.rmtree(extract_dir, ignore_errors=True)

    def submit_run(
        self,
        *,
        job_id: str,
        assessment_id: str,
        image_tag: str,
        container_name: str,
        network_name: str,
        app_port: int,
        host_port: int,
    ) -> JobSubmitResponse:
        """Execute a run job: create network, start container.

        Returns a JobSubmitResponse with target_url.
        """
        # Create network
        ok, output = self._run_docker(
            ["network", "create", "--internal", network_name]
        )
        if not ok and "already exists" not in output:
            return JobSubmitResponse(
                job_id=job_id,
                status="FAILED",
                message=f"Network creation failed: {output[:300]}",
            )

        # Start container with security policy
        docker_args = [
            "run",
            "-d",
            "--name",
            container_name,
            "--network",
            network_name,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "--user",
            self.policy.user,
            "--memory",
            self.policy.memory_limit,
            "--cpus",
            self.policy.cpus,
            "--pids-limit",
            str(self.policy.pids_limit),
            "--publish",
            f"{self.bind_ip}:{host_port}:{app_port}",
            image_tag,
        ]
        ok, output = self._run_docker(docker_args)
        if not ok:
            return JobSubmitResponse(
                job_id=job_id,
                status="FAILED",
                message=f"Container start failed: {output[:300]}",
            )

        target_url = f"http://{self.advertised_host}:{host_port}"
        return JobSubmitResponse(
            job_id=job_id,
            status="RUNNING",
            message="Container started successfully",
            target_url=target_url,
        )

    def submit_cleanup(
        self,
        *,
        job_id: str,
        container_name: str,
        network_name: str,
        image_tag: str,
    ) -> JobCancelResponse:
        """Execute a cleanup job: stop container, remove network, remove image."""
        failures: list[str] = []
        commands = (
            (["stop", container_name], "container stop"),
            (["rm", "-f", container_name], "container removal"),
            (["network", "rm", network_name], "network removal"),
            (["rmi", "-f", image_tag], "image removal"),
        )
        for args, label in commands:
            ok, output = self._run_docker(args, timeout_seconds=30)
            # Cleanup is idempotent: resources already absent count as done.
            if not ok and "no such" not in output.lower() and "not found" not in output.lower():
                failures.append(f"{label}: {output[:160]}")

        if failures:
            return JobCancelResponse(
                job_id=job_id,
                status="FAILED",
                message="; ".join(failures),
            )

        return JobCancelResponse(
            job_id=job_id,
            status="CANCELLED",
            message="Cleanup completed",
        )

    def get_status(
        self, *, job_id: str, container_name: str
    ) -> JobStatusResponse:
        """Get the status of a running container."""
        ok, output = self._run_docker(
            ["ps", "--filter", f"name={container_name}", "--format", "{{.Status}}"]
        )
        if not ok:
            return JobStatusResponse(
                job_id=job_id,
                status="FAILED",
                error=f"Docker ps failed: {output[:300]}",
            )

        if "Up" in output:
            return JobStatusResponse(
                job_id=job_id,
                status="RUNNING",
            )
        elif "Exited" in output:
            return JobStatusResponse(
                job_id=job_id,
                status="COMPLETED",
            )
        else:
            return JobStatusResponse(
                job_id=job_id,
                status="PENDING",
            )

    def get_logs(self, *, job_id: str, container_name: str) -> JobLogsResponse:
        """Get container logs."""
        ok, output = self._run_docker(
            ["logs", "--tail", "100", container_name], timeout_seconds=30
        )
        if not ok:
            return JobLogsResponse(
                job_id=job_id,
                logs=f"Failed to get logs: {output[:300]}",
            )
        return JobLogsResponse(job_id=job_id, logs=output)

    def cancel(self, *, job_id: str, container_name: str) -> JobCancelResponse:
        """Cancel a job: stop and remove container."""
        ok, _output = self._run_docker(["stop", container_name], timeout_seconds=30)
        if not ok:
            self._run_docker(["kill", container_name], timeout_seconds=30)
        self._run_docker(["rm", "-f", container_name], timeout_seconds=30)
        return JobCancelResponse(
            job_id=job_id,
            status="CANCELLED",
            message="Job cancelled",
        )

    def health_check(self) -> bool:
        """Check if Docker daemon is available."""
        ok, _ = self._run_docker(["version", "--format", "{{.Server.Version}}"], timeout_seconds=10)
        return ok
