import pytest
import jwt
import time
from app.services.auth_service import (
    hash_password,
    verify_password,
    generate_access_token,
    generate_refresh_token,
    decode_token,
    generate_totp_secret,
    verify_totp
)


# ── Password hashing ──────────────────────────────────────────────────────────

def test_hash_password_returns_string():
    result = hash_password("TestPassword123!")
    assert isinstance(result, str)

def test_hash_password_not_plaintext():
    password = "TestPassword123!"
    result = hash_password(password)
    assert password not in result

def test_hash_password_starts_with_argon2():
    result = hash_password("TestPassword123!")
    assert result.startswith("$argon2")

def test_two_hashes_of_same_password_are_different():
    # Argon2 uses a random salt — same password hashes differently each time
    h1 = hash_password("TestPassword123!")
    h2 = hash_password("TestPassword123!")
    assert h1 != h2

def test_verify_password_correct():
    hashed = hash_password("TestPassword123!")
    assert verify_password(hashed, "TestPassword123!") is True

def test_verify_password_wrong():
    hashed = hash_password("TestPassword123!")
    assert verify_password(hashed, "WrongPassword123!") is False

def test_verify_password_empty_string():
    hashed = hash_password("TestPassword123!")
    assert verify_password(hashed, "") is False

def test_verify_password_never_raises_exception():
    # Should always return bool, never crash
    result = verify_password("notavalidhash", "anypassword")
    assert result is False


# ── JWT access tokens ─────────────────────────────────────────────────────────

def test_generate_access_token_returns_string(app):
    with app.app_context():
        token = generate_access_token(1)
        assert isinstance(token, str)

def test_access_token_contains_user_id(app):
    with app.app_context():
        token = generate_access_token(42)
        payload = decode_token(token)
        assert payload["user_id"] == 42

def test_access_token_type_is_access(app):
    with app.app_context():
        token = generate_access_token(1)
        payload = decode_token(token)
        assert payload["type"] == "access"

def test_access_token_has_expiry(app):
    with app.app_context():
        token = generate_access_token(1)
        payload = decode_token(token)
        assert "exp" in payload

def test_access_token_expires_in_15_minutes(app):
    with app.app_context():
        token = generate_access_token(1)
        payload = decode_token(token)
        # exp - iat should be ~900 seconds (15 minutes)
        diff = payload["exp"] - payload["iat"]
        assert 890 <= diff <= 910


# ── JWT refresh tokens ────────────────────────────────────────────────────────

def test_refresh_token_type_is_refresh(app):
    with app.app_context():
        token = generate_refresh_token(1)
        payload = decode_token(token)
        assert payload["type"] == "refresh"

def test_refresh_token_expires_in_7_days(app):
    with app.app_context():
        token = generate_refresh_token(1)
        payload = decode_token(token)
        diff = payload["exp"] - payload["iat"]
        # 7 days = 604800 seconds, allow small margin
        assert 604700 <= diff <= 604900

def test_access_and_refresh_tokens_are_different(app):
    with app.app_context():
        access = generate_access_token(1)
        refresh = generate_refresh_token(1)
        assert access != refresh


# ── Token decoding ────────────────────────────────────────────────────────────

def test_decode_token_valid(app):
    with app.app_context():
        token = generate_access_token(1)
        payload = decode_token(token)
        assert payload["user_id"] == 1

def test_decode_token_tampered_raises_error(app):
    with app.app_context():
        token = generate_access_token(1)
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(jwt.InvalidTokenError):
            decode_token(tampered)

def test_decode_token_garbage_raises_error(app):
    with app.app_context():
        with pytest.raises(jwt.InvalidTokenError):
            decode_token("this.is.garbage")


# ── TOTP ──────────────────────────────────────────────────────────────────────

def test_generate_totp_secret_returns_string():
    secret = generate_totp_secret()
    assert isinstance(secret, str)

def test_generate_totp_secret_is_32_chars():
    secret = generate_totp_secret()
    assert len(secret) == 32

def test_two_totp_secrets_are_different():
    assert generate_totp_secret() != generate_totp_secret()

def test_verify_totp_valid_code():
    import pyotp
    secret = generate_totp_secret()
    code = pyotp.TOTP(secret).now()
    assert verify_totp(secret, code) is True

def test_verify_totp_wrong_code():
    secret = generate_totp_secret()
    assert verify_totp(secret, "000000") is False

def test_verify_totp_empty_code():
    secret = generate_totp_secret()
    assert verify_totp(secret, "") is False