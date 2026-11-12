"""Runtime Host self-containment and token parity tests.

The execution plane must not import control-plane packages. These tests fail
if a future change reintroduces ``app.runtime.*`` imports into the Runtime
Host source, and they prove the vendored verifier accepts tokens produced by
the control-plane signer and rejects forged/mismatched tokens.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

_BACKEND = str(Path(__file__).resolve().parent.parent.parent / "backend")
_RUNTIME_HOST = str(Path(__file__).resolve().parent.parent.parent / "runtime_host")
for _p in (_BACKEND, _RUNTIME_HOST):
    if _p in sys.path:
        sys.path.remove(_p)
sys.path.insert(0, _BACKEND)
sys.path.insert(1, _RUNTIME_HOST)

from app.runtime.job_token import (  # noqa: E402
    generate_ed25519_keypair,
    sign_job_token,
)
from runtime_host.app.token_verification import (  # noqa: E402
    JobTokenError,
    verify_job_token,
)

APP_DIR = Path(__file__).resolve().parent.parent / "app"
_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+app(?:\.runtime)?\b", re.MULTILINE)


def _runtime_host_sources() -> list[Path]:
    return sorted(APP_DIR.glob("*.py"))


def test_runtime_host_has_no_control_plane_imports() -> None:
    offenders: list[str] = []
    for path in _runtime_host_sources():
        text = path.read_text(encoding="utf-8")
        # Avoid false positives from prose/docstrings: only match import lines.
        if _IMPORT_RE.search(text):
            offenders.append(path.name)
    assert not offenders, (
        "Runtime Host modules must not import control-plane packages: "
        f"{offenders}"
    )


def test_runtime_host_source_files_present() -> None:
    names = {path.name for path in _runtime_host_sources()}
    assert {"token_verification.py", "schemas.py", "executor.py"} <= names


def test_runtime_host_imports_without_backend_path() -> None:
    """The deployable app must import with only its Docker build context."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import app.main; import sys; "
            "assert not any(name.startswith('app.runtime') for name in sys.modules)",
        ],
        cwd=_RUNTIME_HOST,
        env={"PATH": __import__("os").environ.get("PATH", "")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def _sign(private_key, **overrides):
    payload = {
        "jti": "jti-parity-1",
        "tenant_id": "tenant-1",
        "assessment_id": "assessment-1",
        "job_id": "job-1",
        "operation": "build",
        "resources": ["sentinelx-build-assessment-1"],
        "resource_limits": {"memory": "512m"},
        "token_type": "mutation",
        "ttl_seconds": 300,
        "audience": "runtime-host",
        "issuer": "sentinelx-authorization",
    }
    payload.update(overrides)
    return sign_job_token(private_key, **payload)


def test_control_plane_token_verifies_on_runtime_host() -> None:
    private_key, public_key = generate_ed25519_keypair()
    token = _sign(private_key)

    payload = verify_job_token(
        public_key,
        token,
        expected_operation="build",
        expected_assessment_id="assessment-1",
        expected_tenant_id="tenant-1",
        expected_audience="runtime-host",
        expected_issuer="sentinelx-authorization",
    )

    assert payload["job_id"] == "job-1"
    assert payload["resources"] == ["sentinelx-build-assessment-1"]
    assert payload["token_type"] == "mutation"


def test_tampered_payload_is_rejected() -> None:
    private_key, public_key = generate_ed25519_keypair()
    header, payload, signature = _sign(private_key).split(".")

    # Keep the payload parseable and corrupt only its signature.
    signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    with pytest.raises(JobTokenError, match="Invalid signature"):
        verify_job_token(public_key, f"{header}.{payload}.{signature}")


def test_wrong_audience_is_rejected() -> None:
    private_key, public_key = generate_ed25519_keypair()
    token = _sign(private_key, audience="other-runtime-host")
    with pytest.raises(JobTokenError, match="Audience mismatch"):
        verify_job_token(public_key, token, expected_audience="runtime-host")


def test_expired_token_is_rejected(monkeypatch) -> None:
    private_key, public_key = generate_ed25519_keypair()
    token = _sign(private_key, ttl_seconds=-10)
    with pytest.raises(JobTokenError, match="Token expired"):
        verify_job_token(public_key, token)


def test_algorithm_confusion_is_rejected() -> None:
    private_key, public_key = generate_ed25519_keypair()
    token = _sign(private_key)
    header, payload, signature = token.split(".")
    # Re-encode a header claiming HS256; signature cannot match the Ed25519 key.
    import base64
    import json

    forged_header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    with pytest.raises(JobTokenError, match="Unsupported algorithm"):
        verify_job_token(public_key, f"{forged_header}.{payload}.{signature}")
