"""
Runtime Broker security policy.

The broker decides ALL security parameters. Callers send only minimal
operational parameters; the broker constructs the hardened Docker
invocation and rejects anything that would weaken isolation.

Policy rules:
- Privileged containers: rejected
- Host filesystem mounts / bind mounts: rejected
- Host networking (network_mode=host): rejected
- Host PID namespace (pid_mode=host): rejected
- Root user execution: rejected (non-root enforced from image)
- Arbitrary capabilities: rejected; cap_drop=ALL enforced
- no-new-privileges: enforced
- Read-only rootfs + noexec/nosuid tmpfs: enforced
- CPU / memory / pids limits: enforced
- 127.0.0.1-only port binding: enforced (never 0.0.0.0)
- --internal network only: enforced
- Docker exec: not exposed
- Approved image / build-context policies: enforced
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import get_settings
from app.runtime.broker.schemas import BrokerError

settings = get_settings()

# Naming pattern for all broker-managed Docker resources.
_RESOURCE_NAME_RE = re.compile(r"^sentinelx-(app|cont|net)-[a-z0-9]{1,12}$")

# Approved base image prefixes for generated / pulled images.
APPROVED_IMAGE_PREFIXES = (
    "python:",
    "node:",
    "alpine:",
    "sentinelx-app-",
)


def validate_resource_name(name: str, label: str) -> str:
    """Ensure a Docker resource name follows the sentinelx-*-<assessment> policy."""
    if not name or not _RESOURCE_NAME_RE.match(name):
        raise BrokerError(
            f"{label} '{name}' must follow sentinelx-*-<assessment_id> naming policy.",
            status_code=400,
        )
    return name


def validate_image_tag(image_tag: str) -> str:
    """Ensure the image tag follows the approved naming policy."""
    validate_resource_name(image_tag, "image_tag")
    if not any(image_tag.startswith(prefix) for prefix in APPROVED_IMAGE_PREFIXES):
        raise BrokerError(
            f"Image tag '{image_tag}' uses an unapproved base image.",
            status_code=400,
        )
    return image_tag


def validate_workspace_path(workspace_path: str) -> str:
    """Ensure the build context is under the allowed assessment workspace base.

    The path is resolved (symlinks and ``..`` components normalised) before the
    prefix check, so an attacker cannot escape the workspace base via
    ``../`` traversal or a symlink pointing outside the base.
    """
    base = Path(settings.ASSESSMENT_WORKSPACE_BASE).resolve()
    try:
        path = Path(workspace_path).resolve()
    except (OSError, ValueError):
        raise BrokerError(
            f"Build context '{workspace_path}' cannot be resolved.",
            status_code=400,
        )
    try:
        path.relative_to(base)
    except ValueError:
        raise BrokerError(
            f"Build context '{workspace_path}' is outside {settings.ASSESSMENT_WORKSPACE_BASE}.",
            status_code=400,
        )
    return str(path)


def validate_build_network_mode(network_mode: str) -> str:
    """Build-time network must never be 'host'; default bridge provides no isolation."""
    if network_mode not in ("none", "internal"):
        raise BrokerError(
            f"Build network mode '{network_mode}' is not allowed; use 'none' or 'internal'.",
            status_code=400,
        )
    return network_mode


def validate_container_run_request(
    container_name: str,
    image_tag: str,
    network_name: str,
    app_port: int,
    host_port: int,
) -> Tuple[str, str, str, int, int]:
    """
    Validate a container run request and return the normalized values.

    Rejects:
    - Names that don't follow the sentinelx-*-<assessment> policy
    - Mismatched assessment ids across container/image/network
    - Unsafe port values
    """
    validate_resource_name(container_name, "container_name")
    validate_resource_name(image_tag, "image_tag")
    validate_resource_name(network_name, "network_name")
    validate_image_tag(image_tag)

    # All three names must reference the same assessment id.
    def _assessment_id(name: str) -> str:
        return name.split("-")[-1]

    ids = {
        _assessment_id(container_name),
        _assessment_id(image_tag),
        _assessment_id(network_name),
    }
    if len(ids) != 1:
        raise BrokerError(
            "container_name, image_tag, and network_name must reference the same assessment.",
            status_code=400,
        )

    if not (1024 <= app_port <= 65535) or not (1024 <= host_port <= 65535):
        raise BrokerError("app_port and host_port must be in range 1024-65535.", status_code=400)

    return container_name, image_tag, network_name, app_port, host_port


def build_docker_run_args(
    container_name: str,
    image_tag: str,
    network_name: str,
    app_port: int,
    host_port: int,
) -> List[str]:
    """
    Construct the hardened docker run argument vector.

    The broker decides all security parameters. The caller cannot influence
    capabilities, privileges, mounts, user, or network mode.
    """
    return [
        "docker",
        "run",
        "-d",
        f"--name={container_name}",
        f"--network={network_name}",
        # --- Mandatory isolation controls (enforced by broker) ---
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--read-only",
        f"--tmpfs=/tmp:rw,noexec,nosuid,size={settings.BROKER_TMPFS_SIZE}",
        f"--memory={settings.BROKER_MEMORY_LIMIT}",
        f"--cpus={settings.BROKER_CPUS}",
        f"--pids-limit={settings.BROKER_PIDS_LIMIT}",
        # Non-root user: the image defines the user; broker never overrides to root.
        "--user=appuser",
        # Loopback-only port binding on the host.
        f"-p=127.0.0.1:{host_port}:{app_port}",
        # Explicitly NOT: --privileged, --network=host, --pid=host, -v host paths,
        # --cap-add, --user=root, -e with secrets.
        image_tag,
    ]


def build_docker_build_args(
    workspace_path: str,
    image_tag: str,
    dockerfile_path: Optional[str] = None,
) -> List[str]:
    """
    Construct the hardened docker build argument vector.

    Build-time network is never 'host'. Build context is restricted to the
    approved workspace base.
    """
    args: List[str] = ["docker", "build", "-t", image_tag]
    if settings.BUILD_NETWORK_MODE == "none":
        args.append("--network=none")
    elif settings.BUILD_NETWORK_MODE == "internal":
        args.append("--network=internal")  # requires pre-created internal network
    # Build context last.
    args.append(workspace_path)
    return args


def build_cleanup_args(
    container_name: str,
    network_name: str,
    image_tag: str,
) -> Dict[str, List[str]]:
    """
    Construct the ordered teardown commands: container -> network -> image.

    Order matters: remove the container (releases port binding) before the
    network, then the image.
    """
    return {
        "container": ["docker", "rm", "-f", container_name],
        "network": ["docker", "network", "rm", network_name],
        "image": ["docker", "rmi", image_tag],
    }


def assert_no_dangerous_flags(extra_flags: Optional[Dict[str, Any]] = None) -> None:
    """
    Reject any attempt to pass dangerous Docker flags through the broker.

    The broker never accepts:
    - privileged
    - cap_add / capabilities to add
    - volumes / bind mounts (host paths)
    - network_mode=host
    - pid_mode=host
    - user=root
    - exec commands
    """
    if not extra_flags:
        return
    dangerous_keys = {
        "privileged",
        "cap_add",
        "cap_drop",
        "volumes",
        "volume",
        "mount",
        "network_mode",
        "pid_mode",
        "uts_mode",
        "ipc_mode",
        "user",
        "userns_mode",
        "exec",
        "command",
        "entrypoint",
    }
    found = [k for k in (extra_flags or {}) if k in dangerous_keys]
    if found:
        raise BrokerError(
            f"Dangerous Docker parameters are not allowed through the broker: {', '.join(found)}.",
            status_code=400,
        )
