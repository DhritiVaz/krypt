import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_encryption_key(encryption_salt: bytes, password: bytes) -> bytes:
    """
    Derives a 32-byte AES-256 encryption key from the master password.
    Uses Argon2id — deliberately slow and memory-intensive.
    This key is NEVER stored — derived fresh each time from the master password.
    """
    from argon2.low_level import hash_secret_raw, Type

    key = hash_secret_raw(
        secret=password,
        salt=encryption_salt,
        time_cost=3,        # 3 iterations
        memory_cost=65536,  # 64MB of RAM
        parallelism=4,      # 4 threads
        hash_len=32,        # 32 bytes = 256 bits (AES-256)
        type=Type.ID        # Argon2id variant
    )
    return key


def encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts a string using AES-256-GCM.

    Returns:
        (ciphertext, iv) — both needed for decryption
        ciphertext already includes the GCM auth tag (appended automatically)

    Args:
        plaintext: the string to encrypt (e.g. "mypassword123")
        key: 32-byte encryption key from generate_encryption_key()
    """
    # Generate a fresh random 12-byte IV for every encryption
    # 12 bytes is the recommended size for AES-GCM
    iv = os.urandom(12)

    # Create AES-GCM cipher with our key
    aesgcm = AESGCM(key)

    # Encrypt — returns ciphertext + auth tag combined
    # encode() converts string → bytes (AES works on bytes, not strings)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)

    return ciphertext, iv


def decrypt(ciphertext: bytes, iv: bytes, key: bytes) -> str:
    """
    Decrypts AES-256-GCM ciphertext back to a string.

    Returns:
        The original plaintext string

    Args:
        ciphertext: encrypted bytes (includes auth tag)
        iv: the IV that was used during encryption
        key: same 32-byte key used for encryption
    """
    aesgcm = AESGCM(key)

    # Decrypt — automatically verifies the auth tag
    # If data was tampered with, this raises an InvalidTag exception
    plaintext_bytes = aesgcm.decrypt(iv, ciphertext, None)

    # decode() converts bytes → string
    return plaintext_bytes.decode("utf-8")


def generate_encryption_salt() -> bytes:
    """Generates a random 16-byte salt for key derivation."""
    return os.urandom(16)