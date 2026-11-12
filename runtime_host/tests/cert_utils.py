"""Disposable test certificate helpers.

All certificates are generated at test time. No production key material is
read or written.
"""
from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def utcnow() -> datetime:
    return datetime.now(UTC)


def make_ca(
    common_name: str = "SENTINEL-X Test CA",
    not_before: datetime | None = None,
    not_after: datetime | None = None,
):
    key = ed25519.Ed25519PrivateKey.generate()
    nb = (not_before or utcnow() - timedelta(days=1)).replace(tzinfo=None)
    na = (not_after or utcnow() + timedelta(days=30)).replace(tzinfo=None)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, None)
    )
    return key, cert


def make_client_cert(
    ca_key,
    ca_cert,
    common_name: str = "sentinelx-worker-test",
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    *,
    include_eku: bool = True,
    is_ca: bool = False,
):
    key = ed25519.Ed25519PrivateKey.generate()
    nb = (not_before or utcnow() - timedelta(days=1)).replace(tzinfo=None)
    na = (not_after or utcnow() + timedelta(days=30)).replace(tzinfo=None)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
    )
    if include_eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    return key, builder.sign(ca_key, None)


def make_intermediate_ca(ca_key, ca_cert, common_name: str = "Intermediate CA"):
    """Create an intermediate CA signed by ``ca_key``/``ca_cert``."""
    key = ed25519.Ed25519PrivateKey.generate()
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((utcnow() - timedelta(days=1)).replace(tzinfo=None))
        .not_valid_after((utcnow() + timedelta(days=30)).replace(tzinfo=None))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        .sign(ca_key, None)
    )
    return key, cert


def make_crl(ca_key, ca_cert, revoked_serials=()):
    """Create a CRL signed by the given CA, optionally revoking serials."""
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update((utcnow() - timedelta(days=1)).replace(tzinfo=None))
        .next_update((utcnow() + timedelta(days=7)).replace(tzinfo=None))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
    )
    for serial in revoked_serials:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(
                (utcnow() - timedelta(hours=1)).replace(tzinfo=None)
            )
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    return builder.sign(ca_key, None)


def make_server_cert(ca_key, ca_cert, common_name: str = "localhost"):
    key = ed25519.Ed25519PrivateKey.generate()
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((utcnow() - timedelta(days=1)).replace(tzinfo=None))
        .not_valid_after((utcnow() + timedelta(days=30)).replace(tzinfo=None))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, None)
    )
    return key, cert


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def write_cert(path: Path, cert: x509.Certificate) -> Path:
    path.write_bytes(cert_pem(cert))
    return path


def write_key(path: Path, key) -> Path:
    path.write_bytes(key_pem(key))
    return path


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def crl_pem(crl) -> bytes:
    return crl.public_bytes(serialization.Encoding.PEM)


def write_crl(path: Path, crl) -> Path:
    path.write_bytes(crl_pem(crl))
    return path
