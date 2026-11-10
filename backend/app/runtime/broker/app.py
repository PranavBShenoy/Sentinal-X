"""
SENTINEL-X Runtime Broker FastAPI application.

Exposes a narrow, authenticated interface for Docker operations. The broker
holds the Docker socket and enforces security policy on every request.
The Celery worker never mounts the socket; it talks to this service.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.logging import get_logger
from app.runtime.broker.auth import validate_broker_key_header
from app.runtime.broker.executor import DockerExecutor
from app.runtime.broker.schemas import (
    BrokerError,
    BuildRequest,
    BrokerResponse,
    CleanupRequest,
    ContainerRunRequest,
    HealthResponse,
    NetworkCreateRequest,
)

settings = get_settings()
logger = get_logger(__name__)
executor = DockerExecutor()

app = FastAPI(
    title="SENTINEL-X Runtime Broker",
    description="Policy-enforcing Docker runtime broker for isolated assessments.",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.exception_handler(BrokerError)
async def broker_error_handler(_, exc: BrokerError):
    """Convert broker policy violations to HTTP errors with the right status code."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.message},
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/v1/broker/health", response_model=HealthResponse, tags=["broker"])
def broker_health(
    x_broker_key: str = Header(None),
) -> HealthResponse:
    """Broker liveness and Docker daemon availability."""
    validate_broker_key_header(x_broker_key)
    available, _ = executor.is_available()
    return HealthResponse(
        status="healthy" if available else "degraded",
        docker_available=available,
    )


@app.post("/v1/broker/build", response_model=BrokerResponse, tags=["broker"])
def broker_build(
    request: BuildRequest,
    x_broker_key: str = Header(None),
) -> BrokerResponse:
    """Build an assessment image with hardened build settings."""
    validate_broker_key_header(x_broker_key)
    from app.runtime.broker.policy import (
        validate_build_network_mode,
        validate_image_tag,
        validate_workspace_path,
    )

    validate_workspace_path(request.workspace_path)
    validate_image_tag(request.image_tag)
    validate_build_network_mode(request.network_mode)

    ok, log = executor.build_image(
        workspace_path=request.workspace_path,
        image_tag=request.image_tag,
    )
    if not ok:
        return BrokerResponse(
            ok=False,
            status="build_failed",
            message="Docker image build failed.",
            data={"log": log[:500]},
        )
    return BrokerResponse(
        ok=True,
        status="built",
        message="Image built successfully.",
        data={"image_tag": request.image_tag},
    )


@app.post("/v1/broker/network/create", response_model=BrokerResponse, tags=["broker"])
def broker_network_create(
    request: NetworkCreateRequest,
    x_broker_key: str = Header(None),
) -> BrokerResponse:
    """Create a dedicated --internal network for an assessment."""
    validate_broker_key_header(x_broker_key)
    from app.runtime.broker.policy import validate_resource_name

    validate_resource_name(request.network_name, "network_name")

    ok, log = executor.create_network(request.network_name, internal=request.internal)
    if not ok:
        return BrokerResponse(
            ok=False,
            status="network_create_failed",
            message="Failed to create isolated internal network.",
            data={"log": log[:500]},
        )
    return BrokerResponse(
        ok=True,
        status="network_created",
        message="Isolated internal network created.",
        data={"network_name": request.network_name},
    )


@app.post("/v1/broker/container/run", response_model=BrokerResponse, tags=["broker"])
def broker_container_run(
    request: ContainerRunRequest,
    x_broker_key: str = Header(None),
) -> BrokerResponse:
    """
    Run a hardened container.

    Security parameters are enforced by the broker; the caller supplies only
    operational parameters (names, ports, network).
    """
    validate_broker_key_header(x_broker_key)
    from app.runtime.broker.policy import validate_container_run_request

    validate_container_run_request(
        container_name=request.container_name,
        image_tag=request.image_tag,
        network_name=request.network_name,
        app_port=request.app_port,
        host_port=request.host_port,
    )

    ok, host_port, log = executor.run_container(
        container_name=request.container_name,
        image_tag=request.image_tag,
        network_name=request.network_name,
        app_port=request.app_port,
        host_port=request.host_port,
    )
    if not ok:
        return BrokerResponse(
            ok=False,
            status="container_start_failed",
            message="Failed to start hardened container.",
            data={"log": log[:500]},
        )
    return BrokerResponse(
        ok=True,
        status="running",
        message="Container started with enforced isolation controls.",
        data={
            "container_name": request.container_name,
            "host_port": host_port,
            "target_url": f"http://127.0.0.1:{host_port}",
            "network_name": request.network_name,
            "image_tag": request.image_tag,
        },
    )


@app.get("/v1/broker/container/logs/{container_name}", response_model=Dict[str, Any], tags=["broker"])
def broker_container_logs(
    container_name: str,
    x_broker_key: str = Header(None),
) -> Dict[str, Any]:
    """Get redacted container logs."""
    validate_broker_key_header(x_broker_key)
    from app.runtime.broker.policy import validate_resource_name

    validate_resource_name(container_name, "container_name")
    logs = executor.get_logs(container_name)
    return {"container_name": container_name, "logs": logs}


@app.post("/v1/broker/container/stop", response_model=BrokerResponse, tags=["broker"])
def broker_container_stop(
    container_name: str,
    x_broker_key: str = Header(None),
) -> BrokerResponse:
    """Stop a running container."""
    validate_broker_key_header(x_broker_key)
    from app.runtime.broker.policy import validate_resource_name

    validate_resource_name(container_name, "container_name")
    ok, log = executor.stop_container(container_name)
    return BrokerResponse(
        ok=ok,
        status="stopped" if ok else "stop_failed",
        message="Container stopped." if ok else "Failed to stop container.",
        data={"log": log[:200]},
    )


@app.delete("/v1/broker/container/{container_name}", response_model=BrokerResponse, tags=["broker"])
def broker_container_remove(
    container_name: str,
    x_broker_key: str = Header(None),
) -> BrokerResponse:
    """Remove a container."""
    validate_broker_key_header(x_broker_key)
    from app.runtime.broker.policy import validate_resource_name

    validate_resource_name(container_name, "container_name")
    ok, log = executor.remove_container(container_name)
    return BrokerResponse(
        ok=ok,
        status="removed" if ok else "remove_failed",
        message="Container removed." if ok else "Failed to remove container.",
        data={"log": log[:200]},
    )


@app.delete("/v1/broker/network/{network_name}", response_model=BrokerResponse, tags=["broker"])
def broker_network_remove(
    network_name: str,
    x_broker_key: str = Header(None),
) -> BrokerResponse:
    """Remove a network."""
    validate_broker_key_header(x_broker_key)
    from app.runtime.broker.policy import validate_resource_name

    validate_resource_name(network_name, "network_name")
    ok, log = executor.remove_network(network_name)
    return BrokerResponse(
        ok=ok,
        status="removed" if ok else "remove_failed",
        message="Network removed." if ok else "Failed to remove network.",
        data={"log": log[:200]},
    )


@app.delete("/v1/broker/image/{image_tag}", response_model=BrokerResponse, tags=["broker"])
def broker_image_remove(
    image_tag: str,
    x_broker_key: str = Header(None),
) -> BrokerResponse:
    """Remove a build image."""
    validate_broker_key_header(x_broker_key)
    from app.runtime.broker.policy import validate_image_tag

    validate_image_tag(image_tag)
    ok, log = executor.remove_image(image_tag)
    return BrokerResponse(
        ok=ok,
        status="removed" if ok else "remove_failed",
        message="Image removed." if ok else "Failed to remove image.",
        data={"log": log[:200]},
    )


@app.post("/v1/broker/cleanup", response_model=BrokerResponse, tags=["broker"])
def broker_cleanup(
    request: CleanupRequest,
    x_broker_key: str = Header(None),
) -> BrokerResponse:
    """
    Full ordered teardown for an assessment: container -> network -> image.

    All steps are attempted even if earlier ones fail.
    """
    validate_broker_key_header(x_broker_key)
    from app.runtime.broker.policy import (
        validate_container_run_request,
    )

    validate_container_run_request(
        container_name=request.container_name,
        image_tag=request.image_tag,
        network_name=request.network_name,
        app_port=0,  # not used for cleanup; schema requires it
        host_port=0,  # not used for cleanup; schema requires it
    )

    results = executor.cleanup(
        container_name=request.container_name,
        network_name=request.network_name,
        image_tag=request.image_tag,
    )
    all_ok = all(step.get("ok") for step in results.values())
    return BrokerResponse(
        ok=all_ok,
        status="cleanup_done" if all_ok else "cleanup_partial",
        message="Resources cleaned up." if all_ok else "Partial cleanup; review logs.",
        data={"steps": results},
    )
