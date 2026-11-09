"""
Unit tests for authentication, password hashing, and token cryptography.
"""
from datetime import timedelta
import pytest
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.core.secret_redactor import mask_secret, redact
from app.core.security import (
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)


def test_password_hashing():
    pwd = "ComplexP@ssw0rd123!"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False


def test_jwt_token_creation_and_decoding():
    user_id = "11111111-2222-3333-4444-555555555555"
    token = create_access_token(subject=user_id, extra_claims={"role": "analyst"})
    decoded = decode_access_token(token)

    assert decoded["sub"] == user_id
    assert decoded["role"] == "analyst"
    assert decoded["type"] == "access"


def test_jwt_token_expiration():
    token = create_access_token(subject="expired-user", expires_delta=timedelta(seconds=-10))
    with pytest.raises(ExpiredSignatureError):
        decode_access_token(token)


def test_jwt_invalid_token():
    with pytest.raises(InvalidTokenError):
        decode_access_token("completely-invalid-jwt-token")


def test_refresh_token_generation():
    plain, hashed = generate_refresh_token()
    assert len(plain) > 30
    assert len(hashed) == 64
    assert hash_refresh_token(plain) == hashed


def test_secret_masking():
    token = "test_token_1234567890abcdefghijklmnopqrstuvwxyz"
    masked = mask_secret(token)
    assert "1234567890" not in masked
    assert "..." in masked
    assert len(masked) <= 15


def test_secret_redactor():
    text = "Error connecting with password: 'SuperSecretDBPassword123' at 10.0.0.1"
    cleaned = redact(text)
    assert "SuperSecretDBPassword123" not in cleaned
    assert "[REDACTED" in cleaned
