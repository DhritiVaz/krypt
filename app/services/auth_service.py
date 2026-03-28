import os
import jwt
import pyotp
from datetime import datetime, timezone, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from flask import current_app


# Argon2id hasher — configured to be deliberately slow
# These settings match OWASP recommendations
ph = PasswordHasher(
    time_cost=3,        # 3 iterations
    memory_cost=65536,  # 64MB RAM
    parallelism=4,      # 4 threads
    hash_len=32,        # 32 byte output
    salt_len=16         # 16 byte salt (managed automatically by argon2-cffi)
)


# ─── Password Hashing ────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """
    Hashes a master password using Argon2id.
    Returns a string like: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    The salt is embedded in the hash string automatically.
    """
    return ph.hash(password)


def verify_password(stored_hash: str, provided_password: str) -> bool:
    """
    Verifies a password attempt against a stored Argon2 hash.
    Returns True if correct, False if wrong.
    Never raises an exception to the caller — always returns bool.
    """
    try:
        return ph.verify(stored_hash, provided_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# ─── JWT Tokens ──────────────────────────────────────────────────────────────

def generate_access_token(user_id: int) -> str:
    """
    Creates a short-lived JWT access token (15 minutes).
    Contains the user's ID so we know who they are on each request.
    """
    payload = {
        "user_id": user_id,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "iat": datetime.now(timezone.utc),  # issued at
    }
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")


def generate_refresh_token(user_id: int) -> str:
    """
    Creates a long-lived JWT refresh token (7 days).
    Used to get a new access token without logging in again.
    """
    payload = {
        "user_id": user_id,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")


def decode_token(token: str) -> dict:
    """
    Decodes and validates a JWT token.
    Returns the payload dict if valid.
    Raises jwt.ExpiredSignatureError if expired.
    Raises jwt.InvalidTokenError if tampered with or invalid.
    """
    return jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])


# ─── TOTP / 2FA ──────────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    """
    Generates a random base32 secret for TOTP 2FA.
    This gets stored in the users table and shown to user as QR code once.
    """
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str) -> str:
    """
    Generates the otpauth:// URI for QR code generation.
    User scans this with Google Authenticator.
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name="Krypt")


def verify_totp(secret: str, code: str) -> bool:
    """
    Verifies a 6-digit TOTP code.
    valid_window=1 allows 1 step tolerance (30 seconds either side).
    Returns True if valid, False if wrong or expired.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)