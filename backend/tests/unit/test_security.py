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


def test_fernet_encryption_and_decryption():
    from app.core.security import decrypt_value, encrypt_value

    secret_val = "gho_super_secret_github_oauth_access_token_999"
    encrypted = encrypt_value(secret_val)

    assert encrypted != secret_val
    assert isinstance(encrypted, str)
    decrypted = decrypt_value(encrypted)
    assert decrypted == secret_val


def test_fernet_key_rotation_and_backward_compatibility():
    """Verify that older tokens remain readable when ENCRYPTION_KEY is rotated with fallback keys."""
    from unittest.mock import patch
    from cryptography.fernet import Fernet
    from app.core.security import decrypt_value, encrypt_value, rotate_encrypted_value

    old_key = Fernet.generate_key().decode()
    new_key = Fernet.generate_key().decode()

    # 1. Encrypt under old key
    with patch("app.core.security.settings.ENCRYPTION_KEY", old_key):
        old_ciphertext = encrypt_value("token-encrypted-with-old-key")

    # 2. Rotate configuration: new_key is primary, old_key is fallback
    multi_key_config = f"{new_key},{old_key}"
    with patch("app.core.security.settings.ENCRYPTION_KEY", multi_key_config):
        # Existing token is still readable seamlessly!
        assert decrypt_value(old_ciphertext) == "token-encrypted-with-old-key"

        # New encryptions use new_key
        new_ciphertext = encrypt_value("token-encrypted-with-new-key")
        assert decrypt_value(new_ciphertext) == "token-encrypted-with-new-key"

        # Rotate old token into new primary key
        re_encrypted = rotate_encrypted_value(old_ciphertext)
        assert re_encrypted != old_ciphertext

    # 3. Verify re-encrypted token can now be decrypted with new_key alone
    with patch("app.core.security.settings.ENCRYPTION_KEY", new_key):
        assert decrypt_value(re_encrypted) == "token-encrypted-with-old-key"


def test_fernet_corrupted_ciphertext_fails():
    from cryptography.fernet import InvalidToken
    from app.core.security import decrypt_value

    with pytest.raises(InvalidToken):
        decrypt_value("gAAAAABl-tampered-corrupted-fernet-token-1234567890==")
