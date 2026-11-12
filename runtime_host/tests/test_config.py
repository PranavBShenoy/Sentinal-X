"""Tests for fail-closed Runtime Host configuration loading."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
)
from runtime_host.app.config import (  # noqa: E402
    ConfigError,
    load_advertised_target,
    load_client_ca_from_path,
    load_config,
    load_proxy_token,
    load_public_key_from_path,
    validate_client_ca_pem,
    validate_proxy_token,
)
from runtime_host.tests.cert_utils import (  # noqa: E402
    cert_pem,
    make_ca,
    make_client_cert,
)

VALID_TOKEN = "test-proxy-token-0123456789abcdefABCDEF"


def _write_public_key(path: Path) -> bytes:
    _, public_key = generate_ed25519_keypair()
    pem = serialize_public_key(public_key)
    path.write_bytes(pem)
    return pem


def _write_client_ca(path: Path) -> bytes:
    _, ca_cert = make_ca()
    pem = cert_pem(ca_cert)
    path.write_bytes(pem)
    return pem


def test_loads_valid_public_key(tmp_path):
    key_path = tmp_path / "public_key.pem"
    pem = _write_public_key(key_path)

    assert load_public_key_from_path(str(key_path)) == pem


def test_missing_public_key_path_fails():
    with pytest.raises(ConfigError, match="RUNTIME_HOST_PUBLIC_KEY_PATH"):
        load_public_key_from_path(None)


def test_private_advertised_ip_is_used_for_target_and_bind(monkeypatch):
    monkeypatch.setenv("RUNTIME_HOST_ADVERTISED_IP", "10.20.30.40")
    monkeypatch.delenv("ADVERTISED_HOSTNAME", raising=False)
    monkeypatch.delenv("RUNTIME_HOST_BIND_IP", raising=False)
    assert load_advertised_target() == ("10.20.30.40", "10.20.30.40")


def test_advertised_hostname_requires_private_bind_ip(monkeypatch):
    monkeypatch.delenv("RUNTIME_HOST_ADVERTISED_IP", raising=False)
    monkeypatch.setenv("ADVERTISED_HOSTNAME", "runtime.internal.example")
    monkeypatch.setenv("RUNTIME_HOST_BIND_IP", "192.168.4.10")
    assert load_advertised_target() == ("runtime.internal.example", "192.168.4.10")


def test_public_target_address_is_rejected(monkeypatch):
    monkeypatch.setenv("RUNTIME_HOST_ADVERTISED_IP", "8.8.8.8")
    monkeypatch.delenv("ADVERTISED_HOSTNAME", raising=False)
    with pytest.raises(ConfigError, match="RFC1918"):
        load_advertised_target()


def test_nonexistent_public_key_file_fails(tmp_path):
    with pytest.raises(ConfigError, match="not a readable file"):
        load_public_key_from_path(str(tmp_path / "missing.pem"))


def test_unreadable_public_key_file_fails(tmp_path):
    key_path = tmp_path / "public_key.pem"
    _write_public_key(key_path)
    key_path.chmod(0o000)
    try:
        if os.access(key_path, os.R_OK):
            pytest.skip("running with privileges that bypass file permissions")
        with pytest.raises(ConfigError, match="could not be read"):
            load_public_key_from_path(str(key_path))
    finally:
        key_path.chmod(0o600)


def test_malformed_public_key_fails(tmp_path):
    key_path = tmp_path / "public_key.pem"
    key_path.write_bytes(b"not a pem key")

    with pytest.raises(ConfigError, match="not a valid PEM public key"):
        load_public_key_from_path(str(key_path))


def test_non_ed25519_public_key_fails(tmp_path):
    key_path = tmp_path / "public_key.pem"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    with pytest.raises(ConfigError, match="must be an Ed25519 key"):
        load_public_key_from_path(str(key_path))


def test_empty_public_key_fails(tmp_path):
    key_path = tmp_path / "public_key.pem"
    key_path.write_bytes(b"")

    with pytest.raises(ConfigError, match="empty"):
        load_public_key_from_path(str(key_path))


class TestProxyToken:
    @pytest.mark.parametrize("token", [None, "", "too-short", "a" * 31])
    def test_missing_or_short_token_fails(self, token):
        with pytest.raises(ConfigError, match="RUNTIME_HOST_PROXY_TOKEN"):
            load_proxy_token(token)

    @pytest.mark.parametrize(
        "token",
        [
            "CHANGE_ME_" + "a" * 40,
            "changeme" + "a" * 40,
            "replace_me_" + "a" * 40,
            "placeholder_" + "a" * 40,
        ],
    )
    def test_placeholder_tokens_rejected(self, token):
        with pytest.raises(ConfigError, match="placeholder"):
            validate_proxy_token(token)

    @pytest.mark.parametrize(
        "token",
        [
            " " + "a" * 40,
            "a" * 40 + "!",
            "a" * 40 + ";",
            "a" * 40 + "\u00e9",
            "a" * 20 + " " + "b" * 20,
        ],
    )
    def test_invalid_characters_rejected(self, token):
        with pytest.raises(ConfigError, match="may contain only"):
            validate_proxy_token(token)

    def test_valid_token_accepted(self):
        assert load_proxy_token(VALID_TOKEN) == VALID_TOKEN

    def test_token_from_protected_file(self, tmp_path):
        token_file = tmp_path / "proxy_token"
        token_file.write_text(VALID_TOKEN + "\n")
        token_file.chmod(0o600)

        assert load_proxy_token(token_file=str(token_file)) == VALID_TOKEN

    def test_missing_token_file_fails(self, tmp_path):
        with pytest.raises(
            ConfigError, match="RUNTIME_HOST_PROXY_TOKEN_FILE"
        ):
            load_proxy_token(token_file=str(tmp_path / "missing"))

    def test_empty_token_file_fails(self, tmp_path):
        token_file = tmp_path / "proxy_token"
        token_file.write_text("\n")
        with pytest.raises(ConfigError, match="RUNTIME_HOST_PROXY_TOKEN"):
            load_proxy_token(token_file=str(token_file))


class TestClientCa:
    def test_loads_valid_ca(self, tmp_path):
        ca_path = tmp_path / "client_ca.crt"
        pem = _write_client_ca(ca_path)
        assert load_client_ca_from_path(str(ca_path)) == pem

    def test_missing_path_fails(self):
        with pytest.raises(ConfigError, match="RUNTIME_HOST_CLIENT_CA_PATH"):
            load_client_ca_from_path(None)

    def test_nonexistent_file_fails(self, tmp_path):
        with pytest.raises(ConfigError, match="not a readable file"):
            load_client_ca_from_path(str(tmp_path / "missing.crt"))

    def test_malformed_pem_fails(self):
        with pytest.raises(ConfigError, match="not a valid PEM"):
            validate_client_ca_pem(b"not a certificate")

    def test_empty_pem_fails(self):
        with pytest.raises(ConfigError, match="empty"):
            validate_client_ca_pem(b"")

    def test_non_ca_certificate_rejected(self):
        ca_key, ca_cert = make_ca()
        _, leaf = make_client_cert(ca_key, ca_cert)
        with pytest.raises(ConfigError, match="must be a CA"):
            validate_client_ca_pem(cert_pem(leaf))

    def test_expired_ca_rejected(self):
        from datetime import timedelta

        from runtime_host.tests.cert_utils import utcnow

        now = utcnow()
        _, ca_cert = make_ca(
            not_before=now - timedelta(days=2),
            not_after=now - timedelta(days=1),
        )
        with pytest.raises(ConfigError, match="not currently valid"):
            validate_client_ca_pem(cert_pem(ca_cert))


def test_load_config_from_environment(tmp_path, monkeypatch):
    key_path = tmp_path / "public_key.pem"
    pem = _write_public_key(key_path)
    ca_path = tmp_path / "client_ca.crt"
    ca_pem = _write_client_ca(ca_path)

    monkeypatch.setenv("RUNTIME_HOST_PUBLIC_KEY_PATH", str(key_path))
    monkeypatch.setenv("RUNTIME_HOST_CLIENT_CA_PATH", str(ca_path))
    monkeypatch.setenv("RUNTIME_HOST_PROXY_TOKEN", VALID_TOKEN)
    monkeypatch.setenv("RUNTIME_HOST_AUDIENCE", "runtime-host")
    monkeypatch.setenv("RUNTIME_HOST_ISSUER", "test-issuer")
    monkeypatch.setenv("RUNTIME_HOST_PORT", "9443")
    monkeypatch.delenv("RUNTIME_HOST_PROXY_TOKEN_FILE", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "development")

    config = load_config()
    assert config.public_key_pem == pem
    assert config.client_ca_pem == ca_pem
    assert config.proxy_token == VALID_TOKEN
    assert config.expected_audience == "runtime-host"
    assert config.expected_issuer == "test-issuer"
    assert config.port == 9443


def test_load_config_prefers_token_file(tmp_path, monkeypatch):
    key_path = tmp_path / "public_key.pem"
    _write_public_key(key_path)
    ca_path = tmp_path / "client_ca.crt"
    _write_client_ca(ca_path)
    token_file = tmp_path / "proxy_token"
    token_file.write_text(VALID_TOKEN + "\n")

    monkeypatch.setenv("RUNTIME_HOST_PUBLIC_KEY_PATH", str(key_path))
    monkeypatch.setenv("RUNTIME_HOST_CLIENT_CA_PATH", str(ca_path))
    monkeypatch.setenv("RUNTIME_HOST_PROXY_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("RUNTIME_HOST_PROXY_TOKEN", raising=False)
    monkeypatch.setenv("RUNTIME_HOST_AUDIENCE", "runtime-host")

    assert load_config().proxy_token == VALID_TOKEN


def test_production_requires_audience(tmp_path, monkeypatch):
    key_path = tmp_path / "public_key.pem"
    _write_public_key(key_path)
    ca_path = tmp_path / "client_ca.crt"
    _write_client_ca(ca_path)

    monkeypatch.setenv("RUNTIME_HOST_PUBLIC_KEY_PATH", str(key_path))
    monkeypatch.setenv("RUNTIME_HOST_CLIENT_CA_PATH", str(ca_path))
    monkeypatch.setenv("RUNTIME_HOST_PROXY_TOKEN", VALID_TOKEN)
    monkeypatch.delenv("RUNTIME_HOST_AUDIENCE", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "production")

    with pytest.raises(ConfigError, match="RUNTIME_HOST_AUDIENCE"):
        load_config()


def test_production_with_audience_succeeds(tmp_path, monkeypatch):
    key_path = tmp_path / "public_key.pem"
    _write_public_key(key_path)
    ca_path = tmp_path / "client_ca.crt"
    _write_client_ca(ca_path)

    monkeypatch.setenv("RUNTIME_HOST_PUBLIC_KEY_PATH", str(key_path))
    monkeypatch.setenv("RUNTIME_HOST_CLIENT_CA_PATH", str(ca_path))
    monkeypatch.setenv("RUNTIME_HOST_PROXY_TOKEN", VALID_TOKEN)
    monkeypatch.setenv("RUNTIME_HOST_AUDIENCE", "runtime-host")
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("RUNTIME_HOST_ADVERTISED_IP", "10.20.30.40")

    assert load_config().expected_audience == "runtime-host"


def test_app_env_production_requires_audience(tmp_path, monkeypatch):
    """APP_ENV is the canonical switch and must trigger production checks."""
    key_path = tmp_path / "public_key.pem"
    _write_public_key(key_path)
    ca_path = tmp_path / "client_ca.crt"
    _write_client_ca(ca_path)

    monkeypatch.setenv("RUNTIME_HOST_PUBLIC_KEY_PATH", str(key_path))
    monkeypatch.setenv("RUNTIME_HOST_CLIENT_CA_PATH", str(ca_path))
    monkeypatch.setenv("RUNTIME_HOST_PROXY_TOKEN", VALID_TOKEN)
    monkeypatch.delenv("RUNTIME_HOST_AUDIENCE", raising=False)
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("ENVIRONMENT", raising=False)

    with pytest.raises(ConfigError, match="RUNTIME_HOST_AUDIENCE"):
        load_config()


def test_app_env_takes_precedence_over_environment(tmp_path, monkeypatch):
    """A legacy ENVIRONMENT=production must not override APP_ENV=development."""
    key_path = tmp_path / "public_key.pem"
    _write_public_key(key_path)
    ca_path = tmp_path / "client_ca.crt"
    _write_client_ca(ca_path)

    monkeypatch.setenv("RUNTIME_HOST_PUBLIC_KEY_PATH", str(key_path))
    monkeypatch.setenv("RUNTIME_HOST_CLIENT_CA_PATH", str(ca_path))
    monkeypatch.setenv("RUNTIME_HOST_PROXY_TOKEN", VALID_TOKEN)
    monkeypatch.delenv("RUNTIME_HOST_AUDIENCE", raising=False)
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("ENVIRONMENT", "production")

    assert load_config().expected_audience is None


def test_invalid_port_fails(tmp_path, monkeypatch):
    key_path = tmp_path / "public_key.pem"
    _write_public_key(key_path)
    ca_path = tmp_path / "client_ca.crt"
    _write_client_ca(ca_path)
    monkeypatch.setenv("RUNTIME_HOST_PUBLIC_KEY_PATH", str(key_path))
    monkeypatch.setenv("RUNTIME_HOST_CLIENT_CA_PATH", str(ca_path))
    monkeypatch.setenv("RUNTIME_HOST_PROXY_TOKEN", VALID_TOKEN)
    monkeypatch.setenv("RUNTIME_HOST_PORT", "not-a-port")

    with pytest.raises(ConfigError, match="must be an integer"):
        load_config()


def test_out_of_range_port_fails(tmp_path, monkeypatch):
    key_path = tmp_path / "public_key.pem"
    _write_public_key(key_path)
    ca_path = tmp_path / "client_ca.crt"
    _write_client_ca(ca_path)
    monkeypatch.setenv("RUNTIME_HOST_PUBLIC_KEY_PATH", str(key_path))
    monkeypatch.setenv("RUNTIME_HOST_CLIENT_CA_PATH", str(ca_path))
    monkeypatch.setenv("RUNTIME_HOST_PROXY_TOKEN", VALID_TOKEN)
    monkeypatch.setenv("RUNTIME_HOST_PORT", "70000")

    with pytest.raises(ConfigError, match="between 1 and 65535"):
        load_config()
