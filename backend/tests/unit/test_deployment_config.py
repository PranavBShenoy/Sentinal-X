"""Deployment configuration regression tests.

These tests protect the contract between Docker Compose and the application
settings. They parse the real ``docker-compose.yml`` so a future edit that
drops ``APP_ENV`` cannot silently disable production-only fail-closed checks.
"""
from __future__ import annotations

from pathlib import Path

import pytest

COMPOSE_PATH = Path(__file__).resolve().parents[3] / "docker-compose.yml"

# Services that run Python application code and therefore read APP_ENV.
APP_ENV_SERVICES = ("api", "worker", "broker", "runtime_host")


def _service_block(compose_text: str, service: str) -> str:
    """Return the raw YAML block for a top-level service name.

    The compose file uses two-space indentation for services under
    ``services:``; a block ends at the next line indented by four spaces or
    fewer (excluding blank lines).
    """
    lines = compose_text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == f"{service}:" and line.startswith("  ") and not line.startswith("    "):
            start = index + 1
            break
    if start is None:
        raise AssertionError(f"service {service!r} not found in docker-compose.yml")

    block: list[str] = []
    for line in lines[start:]:
        if not line.strip():
            block.append(line)
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= 2:
            break
        block.append(line)
    return "\n".join(block)


@pytest.mark.parametrize("service", APP_ENV_SERVICES)
def test_service_receives_app_env(service: str) -> None:
    """Every Python service must receive APP_ENV, not only ENVIRONMENT."""
    compose_text = COMPOSE_PATH.read_text(encoding="utf-8")
    block = _service_block(compose_text, service)
    assert "APP_ENV=" in block, (
        f"service {service!r} does not receive APP_ENV; production guards "
        "would silently run in development mode"
    )
