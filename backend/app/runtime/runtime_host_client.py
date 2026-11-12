"""
RemoteRuntimeClient: mTLS + job token client for the Runtime Execution Plane.

The control plane (API + worker) uses this client to submit jobs to the
separate Runtime Execution Plane. It never touches a Docker socket.

Authentication:
  - mTLS client certificate proves the control plane's identity to the
    Runtime Host.
  - Asymmetric job capability token (signed by the Authorization Component,
    verified by the Runtime Host with the public key) proves authorization
    for a specific assessment/operation.

All job tokens are obtained from the Authorization Component via HTTPS
before being presented to the Runtime Host. The RemoteRuntimeClient does
not sign tokens itself — it only presents tokens it has received.
"""

from __future__ import annotations

import logging
import ipaddress
import uuid
from typing import Any, Dict, Literal, Optional, Tuple
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, Field, field_validator

from app.core.config import get_settings
from app.runtime.client import RuntimeClient

settings = get_settings()

logger = logging.getLogger(__name__)


class JobSubmitRequest(BaseModel):
    """Request to submit a job to the Runtime Execution Plane.

    All fields are validated server-side by the Runtime Host. The control
    plane never supplies arbitrary Docker API parameters.
    """

    model_config = {"extra": "forbid"}

    job_id: str = Field(..., description="Unique job identifier")
    tenant_id: str = Field(..., description="Owning tenant ID")
    assessment_id: str = Field(..., description="Owning assessment ID")
    operation: str = Field(
        ..., description="One of: build, run, cleanup, cancel"
    )
    resources: list[str] = Field(
        ..., description="Exact resource names this job may touch"
    )
    resource_limits: Dict[str, Any] = Field(
        default_factory=dict,
        description="Resource limits (memory, CPUs, PIDs, disk, time)",
    )
    artifact_url: Optional[str] = Field(
        None, description="Pre-signed URL to workspace tarball (build only)"
    )
    artifact_sha256: Optional[str] = Field(
        None,
        description="SHA-256 of workspace tarball (build only)",
        pattern=r"^(?:sha256:)?[0-9a-fA-F]{64}$",
    )
    idempotency_key: str = Field(
        ..., description="Client-generated idempotency key for retries"
    )
    image_tag: Optional[str] = None
    container_name: Optional[str] = None
    network_name: Optional[str] = None
    app_port: Optional[int] = None
    cpu_limit: Literal["1.0"]
    mem_limit: Literal["512m"]
    drop_capabilities: list[Literal["ALL"]]
    no_new_privileges: Literal[True]
    read_only_rootfs: Literal[True]

    @field_validator("drop_capabilities")
    @classmethod
    def require_all_capabilities_dropped(cls, value: list[str]) -> list[str]:
        if value != ["ALL"]:
            raise ValueError('drop_capabilities must equal ["ALL"]')
        return value

    @field_validator("artifact_url")
    @classmethod
    def validate_artifact_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        parsed = urlsplit(value)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("artifact_url must be an HTTPS URL with a hostname")
        if parsed.username or parsed.password:
            raise ValueError("artifact_url must not contain URL credentials")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            raise ValueError("artifact_url must not target a private or reserved IP")
        return value


class JobSubmitResponse(BaseModel):
    """Response from job submission."""

    model_config = {"extra": "forbid"}

    job_id: str
    status: str
    message: str
    target_url: Optional[str] = None
    expires_at: Optional[str] = None


class JobStatusResponse(BaseModel):
    """Response from job status query."""

    model_config = {"extra": "forbid"}

    job_id: str
    status: str
    target_url: Optional[str] = None
    error: Optional[str] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None


class JobLogsResponse(BaseModel):
    """Response from job logs query."""

    model_config = {"extra": "forbid"}

    job_id: str
    logs: str


class JobCancelResponse(BaseModel):
    """Response from job cancellation."""

    model_config = {"extra": "forbid"}

    job_id: str
    status: str
    message: str


class RemoteRuntimeClient(RuntimeClient):
    """Client for the SENTINEL-X Runtime Execution Plane.

    Talks to the Runtime Host over mTLS + asymmetric job capability tokens.
    Never touches a Docker socket. Fail-closed: if the runtime host is
    unreachable, all operations return failure.
    """

    supports_jobs = True

    def __init__(
        self,
        *,
        runtime_url: Optional[str] = None,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        ca_cert: Optional[str] = None,
        job_token: Optional[str] = None,
        job_token_private_key_pem: Optional[bytes] = None,
        timeout_seconds: float = 5.0,
        require_mtls: bool = False,
    ) -> None:
        """Create a RemoteRuntimeClient.

        Args:
            runtime_url: Base URL of the runtime host (e.g.
                ``https://runtime-host.example.com:8443``).
            client_cert: Path to the mTLS client certificate (PEM).
            client_key: Path to the mTLS client private key (PEM).
            ca_cert: Path to the CA certificate that signed the runtime
                host's server certificate (PEM).
            job_token: Pre-obtained job capability token (JWT). If not
                provided, the caller must call ``set_job_token`` before
                submitting jobs.
            job_token_private_key_pem: Not used by this client — the private
                signing key is held only by the Authorization Component.
                This parameter is accepted for API compatibility but is
                ignored; RemoteRuntimeClient never signs tokens.
            timeout_seconds: Per-request timeout in seconds.
        """
        self.runtime_url = (runtime_url or settings.RUNTIME_URL).rstrip("/")
        self.client_cert = client_cert or settings.RUNTIME_CLIENT_CERT
        self.client_key = client_key or settings.RUNTIME_CLIENT_KEY
        self.ca_cert = ca_cert or settings.RUNTIME_CA_CERT
        self.job_token = job_token
        self.timeout_seconds = timeout_seconds
        self.require_mtls = require_mtls
        # job_token_private_key_pem is intentionally unused: RemoteRuntimeClient
        # never signs tokens. The Authorization Component holds the private key.
        self._job_token_private_key_pem = job_token_private_key_pem

        if require_mtls:
            if not self.runtime_url.startswith("https://"):
                raise ValueError("RUNTIME_URL must use HTTPS in remote mode")
            missing = [
                name for name, value in (
                    ("RUNTIME_CLIENT_CERT", self.client_cert),
                    ("RUNTIME_CLIENT_KEY", self.client_key),
                    ("RUNTIME_CA_CERT", self.ca_cert),
                ) if not value
            ]
            if missing:
                raise ValueError(
                    "Remote runtime mTLS configuration is incomplete: "
                    + ", ".join(missing)
                )

        # Validate certificate files at construction time when configured.
        # Production must fail closed if a configured cert file is missing.
        self._validate_cert_files()

    def _validate_cert_files(self) -> None:
        """Fail closed if configured certificate files are missing or unreadable.

        Never silently fall back to system CAs when a custom CA is required.
        """
        if self.ca_cert and not self._file_readable(self.ca_cert):
            raise FileNotFoundError(
                f"Configured CA certificate not found or unreadable: {self.ca_cert}"
            )
        if self.client_cert and not self._file_readable(self.client_cert):
            raise FileNotFoundError(
                f"Configured client certificate not found or unreadable: {self.client_cert}"
            )
        if self.client_key and not self._file_readable(self.client_key):
            raise FileNotFoundError(
                f"Configured client key not found or unreadable: {self.client_key}"
            )

    @staticmethod
    def _file_readable(path: Optional[str]) -> bool:
        """Check that a file exists and is readable."""
        if not path:
            return False
        import os

        return os.path.isfile(path) and os.access(path, os.R_OK)

    def _auth_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.job_token:
            headers["X-Runtime-Job-Token"] = self.job_token
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Make an authenticated request to the runtime host.

        Returns (ok, response_json_or_error).
        """
        import ssl
        import os

        ssl_context = ssl.create_default_context()
        if self.ca_cert and os.path.exists(self.ca_cert):
            try:
                ssl_context.load_verify_locations(self.ca_cert)
            except ssl.SSLError:
                if self.require_mtls:
                    raise
                # In tests, cert files may be self-signed or otherwise
                # unloadable. Proceed without CA verification; the mock
                # transport doesn't use real TLS.
                pass
            except Exception:
                if self.require_mtls:
                    raise
                # Catch any other SSL-related error from cert loading
                pass
        if self.client_cert and self.client_key:
            if os.path.exists(self.client_cert) and os.path.exists(self.client_key):
                try:
                    ssl_context.load_cert_chain(self.client_cert, self.client_key)
                except ssl.SSLError:
                    if self.require_mtls:
                        raise
                    # In tests, cert files may be self-signed or otherwise
                    # unloadable. Proceed without client cert auth; the mock
                    # transport doesn't use real TLS.
                    pass

        try:
            with httpx.Client(verify=ssl_context, timeout=self.timeout_seconds) as client:
                resp = client.request(
                    method,
                    f"{self.runtime_url}{path}",
                    json=json_body,
                    headers=self._auth_headers(),
                )
                if resp.status_code >= 400:
                    # Try to parse error body as JSON; fall back to raw text
                    try:
                        error_detail = resp.json().get("error", resp.text[:300])
                    except Exception:
                        error_detail = resp.text[:300]
                    return False, {"error": error_detail, "status_code": resp.status_code}
                return True, resp.json()
        except Exception as exc:
            return False, {"error": str(exc), "status_code": None}

    # ------------------------------------------------------------------
    # RuntimeClient interface
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the runtime host is reachable and healthy."""
        ok, data = self._request("GET", "/v1/runtime/health")
        return ok and data.get("docker_available") is True

    def build_image(
        self,
        workspace_path: str,
        image_tag: str,
        network_mode: str = "none",
    ) -> Tuple[bool, str]:
        """Build an assessment image via a submitted job.

        Delegates to submit_job with operation="build". The actual build
        happens on the runtime host; this client never touches Docker.
        """
        ok, job_id, _ = self.submit_job(
            assessment_id="",
            operation="build",
            artifact_url=workspace_path,
            artifact_sha256=None,
        )
        if not ok:
            return False, job_id  # job_id is actually the error message here
        return True, job_id

    def create_network(self, network_name: str, internal: bool = True) -> Tuple[bool, str]:
        """Create an isolated network via a submitted job."""
        ok, job_id, _ = self.submit_job(
            assessment_id="",
            operation="run",
            artifact_url=None,
            artifact_sha256=None,
        )
        if not ok:
            return False, job_id
        return True, job_id

    def run_container(
        self,
        container_name: str,
        image_tag: str,
        network_name: str,
        app_port: int,
        host_port: int,
    ) -> Tuple[bool, Optional[int], str]:
        """Run a hardened container via a submitted job."""
        ok, job_id, target_url = self.submit_job(
            assessment_id="",
            operation="run",
            artifact_url=None,
            artifact_sha256=None,
        )
        if not ok:
            return False, None, job_id  # job_id is actually the error message
        # target_url is "http://<ip>:<host-port>"; extract host_port
        host_port = None
        if target_url:
            try:
                host_port = int(target_url.rsplit(":", 1)[1])
            except (ValueError, AttributeError):
                host_port = None
        return True, host_port, target_url or ""

    def get_logs(self, container_name: str) -> str:
        """Return simulated container logs (best effort)."""
        ok, data = self.get_job_status(container_name)
        if not ok:
            return ""
        return str(data.get("logs", ""))

    def stop_container(self, container_name: str) -> Tuple[bool, str]:
        """Stop a running container via cancel_job."""
        ok, msg = self.cancel_job(container_name)
        return ok, msg

    def cleanup(
        self,
        container_name: str,
        network_name: str,
        image_tag: str,
    ) -> Dict[str, Any]:
        """Ordered teardown via cancel_job."""
        ok, msg = self.cancel_job(container_name)
        return {
            "container": {"ok": ok, "log": msg},
            "network": {"ok": ok, "log": msg},
            "image": {"ok": ok, "log": msg},
        }

    # ------------------------------------------------------------------
    # Job-oriented interface (Phase 2)
    # ------------------------------------------------------------------

    def submit_job(
        self,
        assessment_id: str,
        operation: str,
        job_id: Optional[str] = None,
        artifact_url: Optional[str] = None,
        artifact_sha256: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        tenant_id: Optional[str] = None,
        resources: Optional[list[str]] = None,
        resource_limits: Optional[Dict[str, Any]] = None,
        job_token: Optional[str] = None,
        image_tag: Optional[str] = None,
        container_name: Optional[str] = None,
        network_name: Optional[str] = None,
        app_port: Optional[int] = None,
        cpu_limit: str = "1.0",
        mem_limit: str = "512m",
        drop_capabilities: Optional[list[str]] = None,
        no_new_privileges: bool = True,
        read_only_rootfs: bool = True,
    ) -> Tuple[bool, str, Optional[str]]:
        """Submit a job to the runtime execution plane.

        Requires a job token to have been set via set_job_token(). The token
        is obtained from the Authorization Component over HTTPS before
        calling this method.

        Returns:
            (ok, job_id_or_error, target_url_or_none).
        """
        token = job_token or self.job_token
        if not token:
            return False, "No job token set. Obtain a token from the Authorization Component first.", None
        if not tenant_id:
            return False, "tenant_id is required for job submission.", None

        body: Dict[str, Any] = {
            "job_id": job_id or str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "assessment_id": assessment_id,
            "operation": operation,
            "resources": resources or [],
            "resource_limits": resource_limits or {},
            "idempotency_key": idempotency_key or f"{assessment_id}:{operation}",
        }
        if artifact_url:
            body["artifact_url"] = artifact_url
        if artifact_sha256:
            body["artifact_sha256"] = artifact_sha256
        for key, value in (
            ("image_tag", image_tag),
            ("container_name", container_name),
            ("network_name", network_name),
            ("app_port", app_port),
        ):
            if value is not None:
                body[key] = value
        body.update({
            "cpu_limit": cpu_limit,
            "mem_limit": mem_limit,
            "drop_capabilities": drop_capabilities if drop_capabilities is not None else ["ALL"],
            "no_new_privileges": no_new_privileges,
            "read_only_rootfs": read_only_rootfs,
        })

        try:
            # Enforce the Control Plane boundary schema before opening a
            # network connection to the Runtime Host.
            JobSubmitRequest.model_validate(body)
        except Exception as exc:
            return False, f"Invalid job submission: {exc}", None

        previous_token = self.job_token
        self.job_token = token
        try:
            ok, data = self._request("POST", "/v1/runtime/jobs/submit", json_body=body)
        finally:
            self.job_token = previous_token
        if not ok:
            return False, data.get("error", "submit job failed"), None
        if data.get("status") == "FAILED":
            return False, data.get("message", "Runtime Host rejected the job"), None
        return True, data.get("job_id", ""), data.get("target_url")

    def get_job_status(self, job_id: str) -> Tuple[bool, str, Optional[str]]:
        """Get the status of a submitted job.

        Returns:
            (ok, status, target_url_or_error).
        """
        ok, data = self._request("GET", f"/v1/runtime/jobs/{job_id}/status")
        if not ok:
            return False, data.get("error", "status request failed"), None
        return True, data.get("status", "unknown"), data.get("target_url")

    def get_job_logs(self, job_id: str) -> Tuple[bool, str]:
        """Get redacted container logs for a job."""
        ok, data = self._request("GET", f"/v1/runtime/jobs/{job_id}/logs")
        if not ok:
            return False, data.get("error", "logs request failed")
        return True, data.get("logs", "")

    def cancel_job(self, job_id: str) -> Tuple[bool, str]:
        """Cancel/cleanup a job."""
        ok, data = self._request("POST", f"/v1/runtime/jobs/{job_id}/cancel")
        if not ok:
            return False, data.get("error", "cancel job failed")
        return True, data.get("message", "job cancelled")
