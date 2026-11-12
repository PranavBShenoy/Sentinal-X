"""
Container security policy for the Runtime Host.

Defines the fixed security policy applied to all containers and builds.
The control plane never supplies arbitrary Docker parameters; the Runtime
Host generates all container configurations internally.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ContainerSecurityPolicy:
    """Immutable container security policy."""

    # Capabilities: drop all, add none
    cap_drop: tuple[str, ...] = ("ALL",)
    cap_add: tuple[str, ...] = ()

    # No new privileges
    no_new_privileges: bool = True

    # Read-only root filesystem
    read_only_rootfs: bool = True

    # Non-root user
    user: str = "10001:10001"

    # No host mounts
    bind_mounts: tuple[str, ...] = ()

    # No host networking
    network_mode: str = "none"  # build uses none; run uses internal bridge

    # No privileged mode
    privileged: bool = False

    # Resource limits
    memory_limit: str = "512m"
    cpus: str = "1.0"
    pids_limit: int = 100

    # No exec after start
    allow_exec: bool = False

    # No tty
    tty: bool = False

    # Build-specific limits
    build_timeout_seconds: int = 180
    build_network_mode: str = "none"

    # Runtime limits
    runtime_timeout_seconds: int = 3600


# Default policy instance
DEFAULT_POLICY = ContainerSecurityPolicy()

# Allowed base image prefixes
ALLOWED_BASE_IMAGES = ("python:", "node:", "alpine:", "sentinelx-app-")

# Maximum number of concurrent jobs
MAX_CONCURRENT_JOBS = 2

# Allowed operations
ALLOWED_OPERATIONS = frozenset({"build", "run", "cleanup", "cancel"})