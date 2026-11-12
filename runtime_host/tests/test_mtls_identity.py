"""Focused tests for trusted-proxy mTLS identity handling."""
from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

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
from runtime_host.app.auth import (  # noqa: E402
    Authenticator,
    normalize_fingerprint,
    validate_fingerprint,
)
from runtime_host.tests.cert_utils import (  # noqa: E402
    cert_pem,
    fingerprint,
    make_ca,
    make_client_cert,
    make_intermediate_ca,
    make_server_cert,
    utcnow,
)

PROXY_TOKEN = "test-proxy-token-0123456789abcdef"
PROXY_HEADER = "X-Runtime-Proxy-Token"
CERT_HEADER = "X-Client-Cert"
FINGERPRINT_HEADER = "X-Client-Cert-SHA256"

CA_KEY, CA_CERT = make_ca()
CA_PEM = cert_pem(CA_CERT)


def _auth(
    require_mtls: bool = True,
    proxy_token: str = PROXY_TOKEN,
    client_ca_pem: bytes | None = CA_PEM,
):
    private_key, public_key = generate_ed25519_keypair()
    auth = Authenticator(
        public_key_pem=serialize_public_key(public_key),
        require_mtls=require_mtls,
        proxy_token=proxy_token if require_mtls else None,
        client_ca_pem=client_ca_pem if require_mtls else None,
    )
    return auth, private_key


def _token(private_key) -> HTTPAuthorizationCredentials:
    token = sign_job_token(
        private_key,
        jti=f"jti-mtls-{uuid.uuid4()}",
        tenant_id="t-tenant",
        assessment_id="a-assessment",
        job_id="j-job",
        operation="build",
        resources=["sentinelx-cont-a-assessment"],
        resource_limits={},
        token_type="mutation",
        ttl_seconds=300,
    )
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


class _Request:
    def __init__(self, headers):
        self.headers = headers


def _cert_headers(
    cert,
    *,
    proxy_token: str = PROXY_TOKEN,
    fingerprint_value=None,
    chain=(),
):
    pem = cert_pem(cert) + b"".join(cert_pem(item) for item in chain)
    headers = {PROXY_HEADER: proxy_token, CERT_HEADER: quote(pem.decode())}
    if fingerprint_value is not None:
        headers[FINGERPRINT_HEADER] = fingerprint_value
    return headers


def _call(auth, headers, credentials):
    request = _Request(headers)
    return asyncio.run(auth.authenticate(request, credentials=credentials))


def _expect_401(auth, headers, credentials):
    with pytest.raises(HTTPException) as exc:
        _call(auth, headers, credentials)
    assert exc.value.status_code == 401


@pytest.fixture(scope="module")
def valid_cert():
    _, cert = make_client_cert(CA_KEY, CA_CERT)
    return cert


def test_valid_certificate_returns_fingerprint(valid_cert):
    auth, private_key = _auth()
    ctx = _call(auth, _cert_headers(valid_cert), _token(private_key))

    assert ctx.worker_fingerprint == fingerprint(valid_cert)
    assert len(ctx.worker_fingerprint) == 64
    assert ctx.worker_cert_subject
    assert "sentinelx-worker-test" in ctx.worker_cert_subject


def test_fingerprint_header_normalized_and_matched(valid_cert):
    auth, private_key = _auth()
    fp = fingerprint(valid_cert).upper()
    colonized = ":".join(fp[i : i + 2] for i in range(0, 64, 2))
    ctx = _call(
        auth,
        _cert_headers(valid_cert, fingerprint_value=colonized),
        _token(private_key),
    )
    assert ctx.worker_fingerprint == fingerprint(valid_cert)


def test_missing_client_certificate_rejected(valid_cert):
    auth, private_key = _auth()
    _expect_401(
        auth,
        {PROXY_HEADER: PROXY_TOKEN},
        _token(private_key),
    )


def test_malformed_client_certificate_rejected():
    auth, private_key = _auth()
    _expect_401(
        auth,
        {PROXY_HEADER: PROXY_TOKEN, CERT_HEADER: "not-a-pem-certificate"},
        _token(private_key),
    )


def test_oversized_client_certificate_header_rejected(valid_cert):
    auth, private_key = _auth()
    _expect_401(
        auth,
        {PROXY_HEADER: PROXY_TOKEN, CERT_HEADER: "a" * (33 * 1024)},
        _token(private_key),
    )


def test_untrusted_certificate_rejected():
    other_key, other_ca = make_ca("Untrusted CA")
    _, cert = make_client_cert(other_key, other_ca)
    auth, private_key = _auth()
    _expect_401(auth, _cert_headers(cert), _token(private_key))


def test_certificate_without_client_auth_eku_rejected():
    ca_key, ca_cert = make_ca()
    _, cert = make_client_cert(ca_key, ca_cert, include_eku=False)
    auth, private_key = _auth(client_ca_pem=cert_pem(ca_cert))
    _expect_401(auth, _cert_headers(cert), _token(private_key))


def test_server_auth_only_certificate_rejected():
    ca_key, ca_cert = make_ca()
    _, cert = make_server_cert(ca_key, ca_cert)
    auth, private_key = _auth(client_ca_pem=cert_pem(ca_cert))
    _expect_401(auth, _cert_headers(cert), _token(private_key))


def test_ca_certificate_as_leaf_rejected():
    ca_key, ca_cert = make_ca()
    _, cert = make_client_cert(ca_key, ca_cert, is_ca=True)
    auth, private_key = _auth(client_ca_pem=cert_pem(ca_cert))
    _expect_401(auth, _cert_headers(cert), _token(private_key))


def test_expired_trust_anchor_rejected():
    now = utcnow()
    ca_key, ca_cert = make_ca(
        not_before=now - timedelta(days=2),
        not_after=now - timedelta(days=1),
    )
    _, cert = make_client_cert(
        ca_key,
        ca_cert,
        not_before=now - timedelta(hours=1),
        not_after=now + timedelta(days=1),
    )
    auth, private_key = _auth(client_ca_pem=cert_pem(ca_cert))
    _expect_401(auth, _cert_headers(cert), _token(private_key))


def test_intermediate_chain_accepted():
    intermediate_key, intermediate_cert = make_intermediate_ca(CA_KEY, CA_CERT)
    _, leaf = make_client_cert(intermediate_key, intermediate_cert)
    auth, private_key = _auth()
    ctx = _call(
        auth,
        _cert_headers(leaf, chain=(intermediate_cert,)),
        _token(private_key),
    )
    assert ctx.worker_fingerprint == fingerprint(leaf)


def test_missing_client_ca_rejected_at_construction():
    with pytest.raises(ValueError, match="client_ca_pem"):
        Authenticator(
            public_key_pem=serialize_public_key(generate_ed25519_keypair()[1]),
            require_mtls=True,
            proxy_token=PROXY_TOKEN,
            client_ca_pem=None,
        )


def test_non_ca_trust_anchor_rejected_at_construction():
    ca_key, ca_cert = make_ca()
    _, leaf = make_client_cert(ca_key, ca_cert)
    with pytest.raises(ValueError, match="must be a CA"):
        Authenticator(
            public_key_pem=serialize_public_key(generate_ed25519_keypair()[1]),
            require_mtls=True,
            proxy_token=PROXY_TOKEN,
            client_ca_pem=cert_pem(leaf),
        )


def test_missing_proxy_token_rejected(valid_cert):
    auth, private_key = _auth()
    _expect_401(
        auth,
        {CERT_HEADER: quote(cert_pem(valid_cert).decode())},
        _token(private_key),
    )


def test_wrong_proxy_token_rejected(valid_cert):
    auth, private_key = _auth()
    _expect_401(
        auth,
        _cert_headers(valid_cert, proxy_token="wrong-proxy-token-0000000000000"),
        _token(private_key),
    )


def test_non_ascii_proxy_token_rejected_without_500(valid_cert):
    """A non-ASCII header must fail authentication, not raise TypeError."""
    auth, private_key = _auth()
    _expect_401(
        auth,
        _cert_headers(valid_cert, proxy_token="\u00e9" * 40),
        _token(private_key),
    )


def test_spoofed_legacy_certificate_header_ignored(valid_cert):
    """x-ssl-client-cert alone is not proof of any certificate."""
    auth, private_key = _auth()
    _expect_401(
        auth,
        {"x-ssl-client-cert": quote(cert_pem(valid_cert).decode())},
        _token(private_key),
    )


def test_supplied_fingerprint_mismatch_rejected(valid_cert):
    auth, private_key = _auth()
    _expect_401(
        auth,
        _cert_headers(valid_cert, fingerprint_value="0" * 64),
        _token(private_key),
    )


def test_malformed_fingerprint_rejected(valid_cert):
    auth, private_key = _auth()
    _expect_401(
        auth,
        _cert_headers(valid_cert, fingerprint_value="a" * 40),
        _token(private_key),
    )


def test_subject_cannot_substitute_for_certificate():
    auth, private_key = _auth()
    _expect_401(
        auth,
        {
            PROXY_HEADER: PROXY_TOKEN,
            "X-Client-Subject": "CN=sentinelx-worker-test",
        },
        _token(private_key),
    )


def test_subject_header_ignored_when_certificate_present(valid_cert):
    auth, private_key = _auth()
    headers = _cert_headers(valid_cert)
    headers["X-Client-Subject"] = "CN=attacker-supplied"
    ctx = _call(auth, headers, _token(private_key))

    assert "attacker-supplied" not in ctx.worker_cert_subject
    assert "sentinelx-worker-test" in ctx.worker_cert_subject


def test_expired_certificate_rejected():
    ca_key, ca_cert = make_ca()
    now = utcnow()
    _, cert = make_client_cert(
        ca_key,
        ca_cert,
        not_before=now - timedelta(days=2),
        not_after=now - timedelta(days=1),
    )
    auth, private_key = _auth(client_ca_pem=cert_pem(ca_cert))
    _expect_401(auth, _cert_headers(cert), _token(private_key))


def test_not_yet_valid_certificate_rejected():
    ca_key, ca_cert = make_ca()
    now = utcnow()
    _, cert = make_client_cert(
        ca_key,
        ca_cert,
        not_before=now + timedelta(days=1),
        not_after=now + timedelta(days=2),
    )
    auth, private_key = _auth(client_ca_pem=cert_pem(ca_cert))
    _expect_401(auth, _cert_headers(cert), _token(private_key))


def test_fingerprint_normalization():
    fp = "AB:CD:EF:" + "0" * 58
    assert normalize_fingerprint(fp) == "abcdef" + "0" * 58
    assert validate_fingerprint(fp) == "abcdef" + "0" * 58
    assert validate_fingerprint("  " + "a" * 64 + "  ")


@pytest.mark.parametrize(
    "value",
    ["", "a" * 63, "a" * 65, "g" * 64, "a" * 40],
)
def test_invalid_fingerprints_rejected(value):
    with pytest.raises(ValueError):
        validate_fingerprint(value)


def test_direct_backend_access_rejected_without_proxy_token(valid_cert):
    """An attacker who reaches the backend still cannot forge identity."""
    auth, private_key = _auth()
    _expect_401(
        auth,
        {
            CERT_HEADER: quote(cert_pem(valid_cert).decode()),
            FINGERPRINT_HEADER: fingerprint(valid_cert),
        },
        _token(private_key),
    )


def test_jwt_verification_still_works_without_mtls():
    """JWT verification behavior is unchanged for the unit-test path."""
    auth, private_key = _auth(require_mtls=False)
    ctx = _call(auth, {}, _token(private_key))
    assert ctx.tenant_id == "t-tenant"
    assert ctx.worker_fingerprint is None
