"""
Safe subprocess execution utilities for SENTINEL-X scanner invocations.

Security rules enforced here:
- Commands must be passed as argument ARRAYS, never as shell strings.
- shell=True is permanently forbidden.
- Secrets are redacted from output before returning.
- Only the tool name and exit code are logged — never full argv.
- Timeouts are always set.
"""
from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Optional

from app.core.secret_redactor import redact

logger = logging.getLogger(__name__)

# Hard cap: no scanner should run longer than this regardless of config
_ABSOLUTE_MAX_TIMEOUT_SECONDS = 600


@dataclass
class SubprocessResult:
    """Result of a subprocess invocation."""

    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    error_message: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def run_command(
    args: List[str],
    timeout_seconds: int = 120,
    capture_output: bool = True,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    tool_name: Optional[str] = None,
) -> SubprocessResult:
    """
    Run an external command safely.

    Parameters
    ----------
    args:
        Command as an argument list. NEVER pass shell-assembled strings.
    timeout_seconds:
        Wall-clock limit. Capped at _ABSOLUTE_MAX_TIMEOUT_SECONDS.
    capture_output:
        If True, capture stdout/stderr; otherwise inherit parent streams.
    cwd:
        Working directory for the subprocess.
    env:
        Environment variables. If None, inherits the parent env.
    tool_name:
        Human-readable name for logging. Defaults to args[0].

    Returns
    -------
    SubprocessResult
        Always returns a result — never raises on subprocess failure.
        Caller should check .exit_code and .timed_out.

    Raises
    ------
    ValueError
        If args is empty or is a plain string (safety guard).
    """
    if not args:
        raise ValueError("args must be a non-empty list")
    if isinstance(args, str):
        raise ValueError(
            "args must be a list, not a string. "
            "Shell string interpolation is forbidden — use argument arrays."
        )

    timeout_seconds = min(timeout_seconds, _ABSOLUTE_MAX_TIMEOUT_SECONDS)
    display_name = tool_name or args[0]

    logger.debug("Launching tool", extra={"tool": display_name})
    start = time.monotonic()

    try:
        proc = subprocess.run(  # noqa: S603 — args is always a list
            args,
            capture_output=capture_output,
            text=True,
            timeout=timeout_seconds,
            cwd=cwd,
            env=env,
            shell=False,  # Explicit: never True
        )
        duration = time.monotonic() - start

        stdout = redact(proc.stdout or "")
        stderr = redact(proc.stderr or "")

        logger.debug(
            "Tool exited",
            extra={"tool": display_name, "exit_code": proc.returncode, "duration_s": f"{duration:.1f}"},
        )

        return SubprocessResult(
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
        )

    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start
        logger.warning("Tool timed out", extra={"tool": display_name, "timeout_s": timeout_seconds})
        return SubprocessResult(
            exit_code=-1,
            stdout="",
            stderr="",
            duration_seconds=duration,
            timed_out=True,
            error_message=f"Tool timed out after {timeout_seconds}s",
        )

    except FileNotFoundError:
        duration = time.monotonic() - start
        logger.info("Tool not found", extra={"tool": display_name})
        return SubprocessResult(
            exit_code=-1,
            stdout="",
            stderr="",
            duration_seconds=duration,
            error_message=f"Tool not found: {display_name}",
        )

    except PermissionError as exc:
        duration = time.monotonic() - start
        logger.error("Permission error running tool", extra={"tool": display_name})
        return SubprocessResult(
            exit_code=-1,
            stdout="",
            stderr="",
            duration_seconds=duration,
            error_message=f"Permission error: {exc}",
        )

    except Exception as exc:  # noqa: BLE001
        duration = time.monotonic() - start
        logger.error("Unexpected error running tool", extra={"tool": display_name, "error": type(exc).__name__})
        return SubprocessResult(
            exit_code=-1,
            stdout="",
            stderr="",
            duration_seconds=duration,
            error_message=f"Unexpected error: {type(exc).__name__}",
        )


def check_tool_available(tool_path: str) -> bool:
    """
    Return True if *tool_path* resolves to an executable binary.
    Uses `which` / shutil.which — does not actually invoke the tool.
    """
    import shutil
    return shutil.which(tool_path) is not None


def get_tool_version(tool_path: str, version_flag: str = "--version") -> Optional[str]:
    """
    Attempt to get tool version string. Returns None if unavailable.
    """
    if not check_tool_available(tool_path):
        return None
    result = run_command([tool_path, version_flag], timeout_seconds=10, tool_name=tool_path)
    if result.succeeded or result.exit_code == 0:
        # Version info may be on stdout or stderr depending on the tool
        output = (result.stdout or result.stderr or "").strip()
        # Return first non-empty line
        for line in output.splitlines():
            if line.strip():
                return line.strip()
    return None
