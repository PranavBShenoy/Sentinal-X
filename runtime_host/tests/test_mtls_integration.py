"""Real TLS integration tests for the shipped Nginx mTLS configuration.

The tests render the actual ``default.conf.template`` with ``envsubst``, start
the actual ``nginx.conf``, execute the actual entrypoint script, and point a
real FastAPI/uvicorn backend at the resulting proxy. They are skipped when
Nginx or envsubst is unavailable.

No Docker and no production certificates are used.
"""
from __future__ import annotations

import contextlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.security import HTTPBearer

_BACKEND = str(Path(__file__).resolve().parent.parent.parent / "backend")
_RUNTIME_HOST = str(Path(__file__).resolve().parent.parent.parent / "runtime_host")
for _p in (_BACKEND, _RUNTIME_HOST):
    if _p in sys.path:
        sys.path.remove(_p)
sys.path.insert(0, _BACKEND)
sys.path.insert(1, _RUNTIME_HOST)

from app.runtime.job_token import (  # noqa: E402
    generate_ed25519_keypair,
    serialize_public_key,
    sign_job_token,
)
from runtime_host.app.auth import Authenticator  # noqa: E402
from runtime_host.tests.cert_utils import (  # noqa: E402
    cert_pem,
    fingerprint,
    make_ca,
    make_client_cert,
    make_crl,
    make_server_cert,
    utcnow,
    write_cert,
    write_crl,
    write_key,
)

def _loopback_sockets_available() -> bool:
    """Return whether this test process can bind a local integration port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    shutil.which("nginx") is None
    or shutil.which("envsubst") is None
    or not _loopback_sockets_available(),
    reason="nginx/envsubst or loopback socket capability is unavailable",
)

PROXY_TOKEN = "integration-proxy-token-0123456789abcdef"
NGINX_DIR = Path(__file__).resolve().parent.parent / "nginx"
TEMPLATE = NGINX_DIR / "templates" / "default.conf.template"
SHIPPED_CONF = NGINX_DIR / "nginx.conf"
ENTRYPOINT = NGINX_DIR / "docker-entrypoint.d" / "40-runtime-host-tls.sh"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _render_shipped_template(sandbox: Path, values: dict[str, str]) -> str:
    template = TEMPLATE.read_text()
    variables = sorted(
        set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", template))
    )
    shell_format = " ".join(f"${{{name}}}" for name in variables)
    env = os.environ.copy()
    env.update(values)
    result = subprocess.run(
        ["envsubst", shell_format],
        input=template,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _adapt_shipped_nginx_conf(sandbox: Path) -> Path:
    """Use the shipped nginx.conf with test-only paths/privilege adjustments."""
    mime = sandbox / "mime.types"
    mime.write_text(
        "types { text/html html; application/octet-stream bin; }\n"
    )

    text = SHIPPED_CONF.read_text()
    text = text.replace("user  nginx;", "# user nginx;  # unprivileged test process")
    text = text.replace(
        "error_log  /var/log/nginx/error.log warn;",
        f"error_log {sandbox}/error.log warn;",
    )
    text = text.replace(
        "pid        /var/run/nginx.pid;", f"pid {sandbox}/nginx.pid;"
    )
    text = text.replace(
        "access_log  /var/log/nginx/access.log  main;",
        f"access_log {sandbox}/access.log main;",
    )
    text = text.replace(
        "include       /etc/nginx/mime.types;", f"include {mime};"
    )
    text = text.replace(
        "include /etc/nginx/conf.d/*.conf;",
        f"include {sandbox}/conf.d/*.conf;",
    )
    temp_paths = (
        f"    client_body_temp_path {sandbox}/client_body;\n"
        f"    proxy_temp_path {sandbox}/proxy;\n"
        f"    fastcgi_temp_path {sandbox}/fastcgi;\n"
        f"    uwsgi_temp_path {sandbox}/uwsgi;\n"
        f"    scgi_temp_path {sandbox}/scgi;\n"
    )
    text = text.replace("http {", "http {\n" + temp_paths, 1)

    config = sandbox / "nginx.conf"
    config.write_text(text)
    return config


def _write_nginx_wrapper(sandbox: Path, config: Path) -> Path:
    """Entrypoint calls ``nginx -t``; point that at the test config."""
    real_nginx = shutil.which("nginx")
    bin_dir = sandbox / "bin"
    bin_dir.mkdir()
    wrapper = bin_dir / "nginx"
    wrapper.write_text(
        "#!/bin/sh\n"
        f'exec "{real_nginx}" -c "{config}" -p "{sandbox}" "$@"\n'
    )
    wrapper.chmod(0o755)
    return bin_dir


def _write_runtime_includes(sandbox: Path, *, token: str = PROXY_TOKEN) -> None:
    runtime = sandbox / "runtime"
    runtime.mkdir()
    (runtime / "token.conf").write_text(
        f'set $runtime_proxy_token "{token}";\n'
    )


def _create_material(sandbox: Path) -> dict:
    certs = sandbox / "certs"
    certs.mkdir()

    server_ca_key, server_ca_cert = make_ca("Server CA")
    client_ca_key, client_ca_cert = make_ca("Client CA")
    server_key, server_cert = make_server_cert(
        server_ca_key, server_ca_cert
    )
    valid_key, valid_cert = make_client_cert(client_ca_key, client_ca_cert)
    second_key, second_cert = make_client_cert(
        client_ca_key,
        client_ca_cert,
        common_name="sentinelx-worker-second",
    )

    untrusted_ca_key, untrusted_ca_cert = make_ca("Untrusted CA")
    untrusted_key, untrusted_cert = make_client_cert(
        untrusted_ca_key, untrusted_ca_cert
    )

    now = utcnow()
    expired_key, expired_cert = make_client_cert(
        client_ca_key,
        client_ca_cert,
        not_before=now - timedelta(days=2),
        not_after=now - timedelta(days=1),
    )
    future_key, future_cert = make_client_cert(
        client_ca_key,
        client_ca_cert,
        not_before=now + timedelta(days=1),
        not_after=now + timedelta(days=2),
    )

    write_cert(certs / "server_ca.crt", server_ca_cert)
    write_cert(certs / "client_ca.crt", client_ca_cert)
    write_cert(certs / "server.crt", server_cert)
    write_key(certs / "server.key", server_key)
    for name, key, cert in (
        ("valid", valid_key, valid_cert),
        ("second", second_key, second_cert),
        ("untrusted", untrusted_key, untrusted_cert),
        ("expired", expired_key, expired_cert),
        ("future", future_key, future_cert),
    ):
        write_cert(certs / f"{name}.crt", cert)
        write_key(certs / f"{name}.key", key)

    return {
        "certs": certs,
        "client_ca_key": client_ca_key,
        "client_ca_cert": client_ca_cert,
        "server_ca_cert": server_ca_cert,
        "valid_cert": valid_cert,
        "second_cert": second_cert,
    }


def _start_backend(client_ca_pem: bytes) -> dict:
    private_key, public_key = generate_ed25519_keypair()
    auth = Authenticator(
        public_key_pem=serialize_public_key(public_key),
        client_ca_pem=client_ca_pem,
        require_mtls=True,
        proxy_token=PROXY_TOKEN,
    )
    app = FastAPI()
    bearer = HTTPBearer(auto_error=False)

    @app.get("/whoami")
    async def whoami(request: Request):
        credentials = await bearer(request)
        ctx = await auth.authenticate(request, credentials=credentials)
        return {
            "fingerprint": ctx.worker_fingerprint,
            "subject": ctx.worker_cert_subject,
        }

    backend_port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app, host="127.0.0.1", port=backend_port, log_level="critical"
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("test backend failed to start")

    token = sign_job_token(
        private_key,
        jti="jti-integration",
        tenant_id="t-tenant",
        assessment_id="a-assessment",
        job_id="j-job",
        operation="build",
        resources=[],
        resource_limits={},
        token_type="read",
        ttl_seconds=300,
    )
    return {"server": server, "thread": thread, "port": backend_port, "token": token}


def _wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("nginx failed to start")


@contextlib.contextmanager
def _stack(
    sandbox: Path,
    *,
    crl_mode: str | None = None,
    require_crl: bool = False,
):
    sandbox.mkdir(parents=True, exist_ok=True)
    material = _create_material(sandbox)
    certs = material["certs"]
    backend = _start_backend(cert_pem(material["client_ca_cert"]))

    runtime = sandbox / "runtime"
    token_path = sandbox / "proxy_token"
    token_path.write_text(PROXY_TOKEN + "\n")

    config = _adapt_shipped_nginx_conf(sandbox)
    bin_dir = _write_nginx_wrapper(sandbox, config)
    frontend_port = _free_port()

    (sandbox / "conf.d").mkdir(exist_ok=True)
    rendered = _render_shipped_template(
        sandbox,
        {
            "NGINX_LISTEN_PORT": str(frontend_port),
            "NGINX_SERVER_NAME": "localhost",
            "NGINX_SERVER_CERT": str(certs / "server.crt"),
            "NGINX_SERVER_KEY": str(certs / "server.key"),
            "NGINX_CLIENT_CA": str(certs / "client_ca.crt"),
            "NGINX_VERIFY_DEPTH": "2",
            "NGINX_RUNTIME_DIR": str(runtime),
            "NGINX_UPSTREAM": f"http://127.0.0.1:{backend['port']}",
        },
    )
    (sandbox / "conf.d" / "default.conf").write_text(rendered)

    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "NGINX_RUNTIME_DIR": str(runtime),
        "NGINX_SERVER_CERT": str(certs / "server.crt"),
        "NGINX_SERVER_KEY": str(certs / "server.key"),
        "NGINX_CLIENT_CA": str(certs / "client_ca.crt"),
        "RUNTIME_HOST_PROXY_TOKEN_FILE": str(token_path),
    }

    if crl_mode == "malformed":
        crl_path = sandbox / "client_ca.crl"
        crl_path.write_text("not a CRL")
        env["NGINX_CLIENT_CRL"] = str(crl_path)
    elif crl_mode in ("empty", "revoked"):
        revoked = (
            [material["valid_cert"].serial_number]
            if crl_mode == "revoked"
            else []
        )
        crl = make_crl(
            material["client_ca_key"],
            material["client_ca_cert"],
            revoked_serials=revoked,
        )
        crl_path = sandbox / "client_ca.crl"
        write_crl(crl_path, crl)
        env["NGINX_CLIENT_CRL"] = str(crl_path)
    if require_crl:
        env["NGINX_REQUIRE_CRL"] = "true"

    entry = subprocess.run(
        ["sh", str(ENTRYPOINT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if entry.returncode != 0:
        backend["server"].should_exit = True
        backend["thread"].join(timeout=5)
        raise AssertionError(f"entrypoint failed: {entry.stderr}")

    nginx = subprocess.Popen(
        [
            shutil.which("nginx"),
            "-c",
            str(config),
            "-p",
            str(sandbox),
            "-g",
            "daemon off;",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_port(frontend_port)
        yield {
            **material,
            "sandbox": sandbox,
            "frontend_port": frontend_port,
            "backend_port": backend["port"],
            "token": backend["token"],
            "nginx": nginx,
        }
    finally:
        nginx.terminate()
        try:
            nginx.wait(timeout=5)
        except subprocess.TimeoutExpired:
            nginx.kill()
        backend["server"].should_exit = True
        backend["thread"].join(timeout=5)


def _request(
    env: dict,
    *,
    cert_name: str | None = "valid",
    headers: dict[str, str] | None = None,
    path: str = "/whoami",
) -> tuple[int, dict]:
    context = ssl.create_default_context(
        cafile=str(env["certs"] / "server_ca.crt")
    )
    context.check_hostname = False
    if cert_name:
        context.load_cert_chain(
            str(env["certs"] / f"{cert_name}.crt"),
            str(env["certs"] / f"{cert_name}.key"),
        )

    conn = http.client.HTTPSConnection(
        "127.0.0.1", env["frontend_port"], context=context, timeout=5
    )
    try:
        conn.request("GET", path, headers=headers or {})
        response = conn.getresponse()
        body = response.read()
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"raw": body.decode("utf-8", "replace")}
        return response.status, parsed
    finally:
        conn.close()


def _auth_headers(env: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {env['token']}"}


def _attempt(env: dict, cert_name: str | None, headers: dict[str, str]):
    try:
        status, body = _request(env, cert_name=cert_name, headers=headers)
        return "status", status, body
    except (ssl.SSLError, OSError) as exc:
        return "error", exc, None


@pytest.fixture(scope="module")
def tls_env(tmp_path_factory):
    sandbox = tmp_path_factory.mktemp("mtls")
    with _stack(sandbox) as env:
        yield env


def test_valid_certificate_is_accepted_with_correct_fingerprint(tls_env):
    status, body = _request(tls_env, headers=_auth_headers(tls_env))
    assert status == 200
    assert body["fingerprint"] == fingerprint(tls_env["valid_cert"])
    assert "sentinelx-worker-test" in body["subject"]


def test_rendered_configuration_excludes_proxy_token(tls_env):
    rendered = (tls_env["sandbox"] / "conf.d" / "default.conf").read_text()
    assert PROXY_TOKEN not in rendered

    token_conf = tls_env["sandbox"] / "runtime" / "token.conf"
    assert token_conf.read_text() == (
        f'set $runtime_proxy_token "{PROXY_TOKEN}";\n'
    )
    assert stat.S_IMODE(token_conf.stat().st_mode) == 0o600


def test_missing_client_certificate_is_rejected(tls_env):
    kind, result, _ = _attempt(tls_env, None, _auth_headers(tls_env))
    assert kind == "error" or result >= 400


def test_untrusted_client_certificate_is_rejected(tls_env):
    kind, result, _ = _attempt(
        tls_env, "untrusted", _auth_headers(tls_env)
    )
    assert kind == "error" or result >= 400


def test_expired_client_certificate_is_rejected(tls_env):
    kind, result, _ = _attempt(tls_env, "expired", _auth_headers(tls_env))
    assert kind == "error" or result >= 400


def test_not_yet_valid_client_certificate_is_rejected(tls_env):
    kind, result, _ = _attempt(tls_env, "future", _auth_headers(tls_env))
    assert kind == "error" or result >= 400


def test_spoofed_identity_headers_are_overwritten(tls_env):
    _, other_cert = make_client_cert(*make_ca())
    headers = _auth_headers(tls_env)
    headers["X-Client-Cert"] = quote(cert_pem(other_cert).decode())
    headers["X-SSL-Client-Cert"] = quote(cert_pem(other_cert).decode())
    headers["X-Runtime-Proxy-Token"] = "attacker-token-000000000000"

    status, body = _request(tls_env, headers=headers)
    assert status == 200
    assert body["fingerprint"] == fingerprint(tls_env["valid_cert"])


def test_direct_backend_access_cannot_authenticate(tls_env):
    """Even if the backend port is reachable, proxy identity is required."""
    conn = http.client.HTTPConnection(
        "127.0.0.1", tls_env["backend_port"], timeout=5
    )
    try:
        conn.request("GET", "/whoami", headers=_auth_headers(tls_env))
        response = conn.getresponse()
        response.read()
        assert response.status == 401
    finally:
        conn.close()


def test_valid_crl_keeps_unrevoked_certificate_usable(tmp_path):
    with _stack(tmp_path, crl_mode="empty") as env:
        status, _ = _request(env, headers=_auth_headers(env))
        assert status == 200


def test_revoked_certificate_is_rejected_and_other_cert_still_works(tmp_path):
    with _stack(tmp_path, crl_mode="revoked") as env:
        kind, result, _ = _attempt(env, "valid", _auth_headers(env))
        assert kind == "error" or result >= 400

        status, body = _request(
            env, cert_name="second", headers=_auth_headers(env)
        )
        assert status == 200
        assert body["fingerprint"] == fingerprint(env["second_cert"])


def test_malformed_crl_fails_entrypoint(tmp_path):
    with pytest.raises(AssertionError, match="entrypoint failed"):
        with _stack(tmp_path, crl_mode="malformed"):
            pass


def test_missing_required_crl_fails_entrypoint(tmp_path):
    with pytest.raises(AssertionError, match="entrypoint failed"):
        with _stack(tmp_path, require_crl=True):
            pass


def _prepare_bad_config(sandbox: Path, *, ca_cert: Path) -> Path:
    (sandbox / "conf.d").mkdir()
    _write_runtime_includes(sandbox)
    config = _adapt_shipped_nginx_conf(sandbox)
    certs = sandbox / "certs"
    certs.mkdir()
    ca_key, server_ca = make_ca()
    server_key, server_cert = make_server_cert(ca_key, server_ca)
    write_cert(certs / "server.crt", server_cert)
    write_key(certs / "server.key", server_key)
    rendered = _render_shipped_template(
        sandbox,
        {
            "NGINX_LISTEN_PORT": str(_free_port()),
            "NGINX_SERVER_NAME": "localhost",
            "NGINX_SERVER_CERT": str(certs / "server.crt"),
            "NGINX_SERVER_KEY": str(certs / "server.key"),
            "NGINX_CLIENT_CA": str(ca_cert),
            "NGINX_VERIFY_DEPTH": "2",
            "NGINX_RUNTIME_DIR": str(sandbox / "runtime"),
            "NGINX_UPSTREAM": "http://127.0.0.1:1",
        },
    )
    (sandbox / "conf.d" / "default.conf").write_text(rendered)
    return config


def test_rendered_config_with_missing_certificate_fails_nginx_check(tmp_path):
    ca_key, ca_cert = make_ca()
    ca_path = tmp_path / "client_ca.crt"
    write_cert(ca_path, ca_cert)
    config = _prepare_bad_config(tmp_path, ca_cert=ca_path)
    (tmp_path / "certs" / "server.crt").unlink()
    result = subprocess.run(
        [
            shutil.which("nginx"),
            "-t",
            "-c",
            str(config),
            "-p",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_rendered_config_with_malformed_ca_fails_nginx_check(tmp_path):
    ca_path = tmp_path / "bad-ca.crt"
    ca_path.write_text("not a certificate")
    config = _prepare_bad_config(tmp_path, ca_cert=ca_path)
    result = subprocess.run(
        [
            shutil.which("nginx"),
            "-t",
            "-c",
            str(config),
            "-p",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_rendered_config_with_missing_ca_fails_nginx_check(tmp_path):
    config = _prepare_bad_config(
        tmp_path, ca_cert=tmp_path / "missing-ca.crt"
    )
    result = subprocess.run(
        [
            shutil.which("nginx"),
            "-t",
            "-c",
            str(config),
            "-p",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
