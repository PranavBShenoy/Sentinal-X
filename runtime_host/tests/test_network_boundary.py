"""Static and runtime-script tests for the Runtime Host trust boundary."""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

from runtime_host.tests.cert_utils import (
    make_ca,
    make_crl,
    make_server_cert,
    write_cert,
    write_crl,
    write_key,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"
NGINX_DIR = REPO_ROOT / "runtime_host" / "nginx"
ENTRYPOINT = NGINX_DIR / "docker-entrypoint.d" / "40-runtime-host-tls.sh"

VALID_TOKEN = "A" * 48


def _compose() -> dict:
    return yaml.safe_load(COMPOSE_PATH.read_text())


def _env_dict(service: dict) -> dict[str, str]:
    result = {}
    for item in service.get("environment", []):
        key, _, value = str(item).partition("=")
        result[key] = value
    return result


def _cert_bind_sources(service: dict) -> list[str]:
    sources = []
    for volume in service.get("volumes", []):
        source = str(volume).split(":", 1)[0]
        if "certs" in source:
            sources.append(source)
    return sources


# ---------------------------------------------------------------------------
# Compose boundary and secret handling
# ---------------------------------------------------------------------------


def test_runtime_host_backend_has_no_published_port():
    service = _compose()["services"]["runtime_host"]
    assert "ports" not in service


def test_only_proxy_publishes_the_runtime_port():
    services = _compose()["services"]
    publishers = {
        name
        for name, svc in services.items()
        if any("8443" in str(port) for port in svc.get("ports", []))
    }
    assert publishers == {"runtime_host_proxy"}


def test_runtime_host_is_only_on_private_edge_network():
    services = _compose()["services"]
    backend_networks = set(services["runtime_host"]["networks"])
    assert backend_networks == {"sentinelx-runtime-edge"}
    assert "sentinelx-runtime-edge" in services["runtime_host_proxy"]["networks"]


def test_proxy_is_the_only_shared_edge_member():
    services = _compose()["services"]
    edge_members = {
        name
        for name, svc in services.items()
        if "sentinelx-runtime-edge" in svc.get("networks", [])
    }
    assert edge_members == {"runtime_host", "runtime_host_proxy"}


def test_api_reaches_proxy_not_backend():
    services = _compose()["services"]
    api_networks = set(services["api"]["networks"])
    assert "sentinelx-runtime" in api_networks
    assert "sentinelx-runtime-edge" not in api_networks
    assert "sentinelx-runtime" in services["runtime_host_proxy"]["networks"]


def test_no_docker_socket_mounted():
    services = _compose()["services"]
    for name in ("runtime_host", "runtime_host_proxy"):
        for volume in services[name].get("volumes", []):
            assert "docker.sock" not in str(volume), name


def test_backend_mounts_only_public_material():
    service = _compose()["services"]["runtime_host"]
    sources = _cert_bind_sources(service)

    assert sources
    for source in sources:
        assert source.endswith(("public_key.pem", "client_ca.crt")), source
        assert not source.endswith("/certs"), source

    joined = " ".join(sources)
    for forbidden in ("ca.key", "client.key", "client.crt", "server.key"):
        assert forbidden not in joined


def test_proxy_mounts_only_server_material_and_public_ca():
    service = _compose()["services"]["runtime_host_proxy"]
    sources = _cert_bind_sources(service)

    assert any(source.endswith("server/server.crt") for source in sources)
    assert any(source.endswith("server/server.key") for source in sources)
    assert any(source.endswith("server/client_ca.crt") for source in sources)

    joined = " ".join(sources)
    for forbidden in ("ca.key", "client.key", "client.crt", "server_ca.key"):
        assert forbidden not in joined
    assert not any(source.endswith("/certs") for source in sources)


def test_proxy_token_uses_secret_file_not_environment():
    services = _compose()["services"]
    for name in ("runtime_host", "runtime_host_proxy"):
        env = _env_dict(services[name])
        assert "RUNTIME_HOST_PROXY_TOKEN" not in env, name
        assert (
            env["RUNTIME_HOST_PROXY_TOKEN_FILE"]
            == "/run/secrets/runtime_host_proxy_token"
        ), name
        assert "runtime_host_proxy_token" in services[name]["secrets"], name


def test_top_level_secret_is_declared():
    secrets = _compose()["secrets"]
    assert "runtime_host_proxy_token" in secrets
    assert secrets["runtime_host_proxy_token"]["file"]


def test_runtime_services_enable_no_new_privileges():
    services = _compose()["services"]
    for name in ("runtime_host", "runtime_host_proxy"):
        assert "no-new-privileges:true" in services[name]["security_opt"], name


# ---------------------------------------------------------------------------
# Shipped Nginx configuration
# ---------------------------------------------------------------------------


def test_nginx_requires_and_verifies_client_certificates():
    template = (
        NGINX_DIR / "templates" / "default.conf.template"
    ).read_text()

    assert "ssl_verify_client on;" in template
    assert "ssl_client_certificate ${NGINX_CLIENT_CA};" in template
    assert "ssl_verify_depth ${NGINX_VERIFY_DEPTH};" in template
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in template
    assert "TLSv1 " not in template
    assert "TLSv1.1" not in template
    assert "include ${NGINX_RUNTIME_DIR}/crl*.conf;" in template
    assert "include ${NGINX_RUNTIME_DIR}/token.conf;" in template


def test_nginx_strips_and_reinjects_identity_headers():
    template = (
        NGINX_DIR / "templates" / "default.conf.template"
    ).read_text()

    for legacy in (
        "X-SSL-Client-Cert",
        "X-SSL-Client-Fingerprint",
        "X-Client-Fingerprint",
        "X-Client-Cert-Fingerprint",
        "X-Client-Cert-SHA256",
    ):
        assert f'proxy_set_header {legacy} "";' in template

    assert "proxy_set_header X-Client-Cert $ssl_client_escaped_cert;" in template
    assert (
        "proxy_set_header X-Runtime-Proxy-Token $runtime_proxy_token;"
        in template
    )
    assert "${RUNTIME_HOST_PROXY_TOKEN}" not in template


# ---------------------------------------------------------------------------
# Actual entrypoint execution
# ---------------------------------------------------------------------------


def _entrypoint_env(
    tmp_path: Path,
    *,
    token: str | None = VALID_TOKEN,
    token_file: bool = True,
) -> dict[str, str]:
    certs = tmp_path / "certs"
    certs.mkdir()
    ca_key, ca_cert = make_ca()
    server_key, server_cert = make_server_cert(ca_key, ca_cert)
    write_cert(certs / "server.crt", server_cert)
    write_key(certs / "server.key", server_key)
    write_cert(certs / "client_ca.crt", ca_cert)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_nginx = bin_dir / "nginx"
    fake_nginx.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" > "$NGINX_FAKE_MARKER"\n'
        "exit 0\n"
    )
    fake_nginx.chmod(0o755)

    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "NGINX_RUNTIME_DIR": str(tmp_path / "runtime"),
        "NGINX_SERVER_CERT": str(certs / "server.crt"),
        "NGINX_SERVER_KEY": str(certs / "server.key"),
        "NGINX_CLIENT_CA": str(certs / "client_ca.crt"),
        "NGINX_FAKE_MARKER": str(tmp_path / "nginx-invoked"),
    }
    if token_file:
        token_path = tmp_path / "proxy_token"
        token_path.write_text((token or "") + "\n")
        token_path.chmod(0o600)
        env["RUNTIME_HOST_PROXY_TOKEN_FILE"] = str(token_path)
    elif token is not None:
        env["RUNTIME_HOST_PROXY_TOKEN"] = token
    return env


def _run_entrypoint(env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sh", str(ENTRYPOINT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_entrypoint_writes_protected_token_include(tmp_path):
    env = _entrypoint_env(tmp_path)
    result = _run_entrypoint(env)
    assert result.returncode == 0, result.stderr

    token_conf = Path(env["NGINX_RUNTIME_DIR"]) / "token.conf"
    assert token_conf.read_text() == (
        f'set $runtime_proxy_token "{VALID_TOKEN}";\n'
    )
    mode = stat.S_IMODE(token_conf.stat().st_mode)
    assert mode == 0o600
    assert VALID_TOKEN not in result.stdout + result.stderr
    assert Path(env["NGINX_FAKE_MARKER"]).exists()


def test_entrypoint_token_env_fallback(tmp_path):
    env = _entrypoint_env(tmp_path, token_file=False)
    result = _run_entrypoint(env)
    assert result.returncode == 0, result.stderr
    token_conf = Path(env["NGINX_RUNTIME_DIR"]) / "token.conf"
    assert VALID_TOKEN in token_conf.read_text()


@pytest.mark.parametrize(
    "name", ["NGINX_SERVER_CERT", "NGINX_SERVER_KEY", "NGINX_CLIENT_CA"]
)
def test_entrypoint_fails_closed_when_tls_material_missing(tmp_path, name):
    env = _entrypoint_env(tmp_path)
    env[name] = str(tmp_path / "missing")
    result = _run_entrypoint(env)
    assert result.returncode != 0
    assert "missing or unreadable" in result.stderr


@pytest.mark.parametrize(
    "token",
    [
        "A" * 31,
        "CHANGE_ME_" + "A" * 40,
        "A" * 40 + "!",
        "A" * 20 + " " + "B" * 20,
        "\u00e9" * 40,
        "",
    ],
)
def test_entrypoint_rejects_invalid_tokens(tmp_path, token):
    env = _entrypoint_env(tmp_path, token=token)
    result = _run_entrypoint(env)
    assert result.returncode != 0
    assert "RUNTIME_HOST_PROXY_TOKEN" in result.stderr


def test_entrypoint_rejects_missing_token_file(tmp_path):
    env = _entrypoint_env(tmp_path)
    env["RUNTIME_HOST_PROXY_TOKEN_FILE"] = str(tmp_path / "missing-token")
    result = _run_entrypoint(env)
    assert result.returncode != 0
    assert "RUNTIME_HOST_PROXY_TOKEN_FILE" in result.stderr


def test_entrypoint_accepts_valid_crl(tmp_path):
    env = _entrypoint_env(tmp_path)
    # The entrypoint validates CRL structure; the issuer match is enforced by
    # OpenSSL/Nginx and is covered by the real TLS integration tests.
    crl_key, crl_ca = make_ca()
    crl_path = tmp_path / "client_ca.crl"
    write_crl(crl_path, make_crl(crl_key, crl_ca))
    env["NGINX_CLIENT_CRL"] = str(crl_path)

    result = _run_entrypoint(env)
    assert result.returncode == 0, result.stderr
    crl_conf = Path(env["NGINX_RUNTIME_DIR"]) / "crl.conf"
    assert crl_conf.read_text() == f"ssl_crl {crl_path};\n"
    assert stat.S_IMODE(crl_conf.stat().st_mode) == 0o600


def test_entrypoint_rejects_malformed_crl(tmp_path):
    env = _entrypoint_env(tmp_path)
    crl_path = tmp_path / "bad.crl"
    crl_path.write_text("not a CRL")
    env["NGINX_CLIENT_CRL"] = str(crl_path)
    result = _run_entrypoint(env)
    assert result.returncode != 0
    assert "not a valid CRL" in result.stderr


def test_entrypoint_requires_crl_when_configured(tmp_path):
    env = _entrypoint_env(tmp_path)
    env["NGINX_REQUIRE_CRL"] = "true"
    result = _run_entrypoint(env)
    assert result.returncode != 0
    assert "NGINX_REQUIRE_CRL=true" in result.stderr
