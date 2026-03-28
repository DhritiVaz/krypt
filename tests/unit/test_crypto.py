import pytest
from app.services.crypto_service import (
    generate_encryption_salt,
    generate_encryption_key,
    encrypt,
    decrypt
)


# ── Salt generation ───────────────────────────────────────────────────────────

def test_generate_salt_returns_16_bytes():
    salt = generate_encryption_salt()
    assert len(salt) == 16

def test_generate_salt_is_random():
    # Two salts should never be identical
    assert generate_encryption_salt() != generate_encryption_salt()

def test_generate_salt_returns_bytes():
    assert isinstance(generate_encryption_salt(), bytes)


# ── Key derivation ────────────────────────────────────────────────────────────

def test_key_is_32_bytes():
    salt = generate_encryption_salt()
    key = generate_encryption_key(salt, b"masterpassword")
    assert len(key) == 32

def test_same_password_same_salt_produces_same_key():
    salt = generate_encryption_salt()
    key1 = generate_encryption_key(salt, b"masterpassword")
    key2 = generate_encryption_key(salt, b"masterpassword")
    assert key1 == key2

def test_different_salt_produces_different_key():
    salt1 = generate_encryption_salt()
    salt2 = generate_encryption_salt()
    key1 = generate_encryption_key(salt1, b"masterpassword")
    key2 = generate_encryption_key(salt2, b"masterpassword")
    assert key1 != key2

def test_different_password_produces_different_key():
    salt = generate_encryption_salt()
    key1 = generate_encryption_key(salt, b"password1")
    key2 = generate_encryption_key(salt, b"password2")
    assert key1 != key2


# ── Encryption ────────────────────────────────────────────────────────────────

def test_encrypt_returns_bytes_and_iv():
    salt = generate_encryption_salt()
    key = generate_encryption_key(salt, b"masterpassword")
    ciphertext, iv = encrypt("mysecretpassword", key)
    assert isinstance(ciphertext, bytes)
    assert isinstance(iv, bytes)

def test_iv_is_12_bytes():
    salt = generate_encryption_salt()
    key = generate_encryption_key(salt, b"masterpassword")
    _, iv = encrypt("mysecretpassword", key)
    assert len(iv) == 12

def test_encrypt_produces_different_ciphertext_each_time():
    # Same plaintext + same key should produce different ciphertext (different IV each time)
    salt = generate_encryption_salt()
    key = generate_encryption_key(salt, b"masterpassword")
    ct1, _ = encrypt("mysecretpassword", key)
    ct2, _ = encrypt("mysecretpassword", key)
    assert ct1 != ct2

def test_ciphertext_not_equal_to_plaintext():
    salt = generate_encryption_salt()
    key = generate_encryption_key(salt, b"masterpassword")
    ciphertext, _ = encrypt("mysecretpassword", key)
    assert ciphertext != b"mysecretpassword"


# ── Decryption ────────────────────────────────────────────────────────────────

def test_decrypt_returns_original_plaintext():
    salt = generate_encryption_salt()
    key = generate_encryption_key(salt, b"masterpassword")
    ciphertext, iv = encrypt("mysecretpassword", key)
    result = decrypt(ciphertext, iv, key)
    assert result == "mysecretpassword"

def test_decrypt_with_wrong_key_fails():
    salt = generate_encryption_salt()
    key1 = generate_encryption_key(salt, b"correctpassword")
    key2 = generate_encryption_key(salt, b"wrongpassword")
    ciphertext, iv = encrypt("mysecretpassword", key1)
    with pytest.raises(Exception):
        decrypt(ciphertext, iv, key2)

def test_decrypt_with_wrong_iv_fails():
    import os
    salt = generate_encryption_salt()
    key = generate_encryption_key(salt, b"masterpassword")
    ciphertext, _ = encrypt("mysecretpassword", key)
    wrong_iv = os.urandom(12)
    with pytest.raises(Exception):
        decrypt(ciphertext, wrong_iv, key)

def test_encrypt_decrypt_empty_string():
    salt = generate_encryption_salt()
    key = generate_encryption_key(salt, b"masterpassword")
    ciphertext, iv = encrypt("", key)
    assert decrypt(ciphertext, iv, key) == ""

def test_encrypt_decrypt_long_string():
    salt = generate_encryption_salt()
    key = generate_encryption_key(salt, b"masterpassword")
    long_text = "a" * 10000
    ciphertext, iv = encrypt(long_text, key)
    assert decrypt(ciphertext, iv, key) == long_text

def test_encrypt_decrypt_special_characters():
    salt = generate_encryption_salt()
    key = generate_encryption_key(salt, b"masterpassword")
    special = "p@$$w0rd!#%^&*()_+-=[]{}|;':\",./<>?"
    ciphertext, iv = encrypt(special, key)
    assert decrypt(ciphertext, iv, key) == special

def test_encrypt_decrypt_unicode():
    salt = generate_encryption_salt()
    key = generate_encryption_key(salt, b"masterpassword")
    unicode_text = "密码123 пароль"
    ciphertext, iv = encrypt(unicode_text, key)
    assert decrypt(ciphertext, iv, key) == unicode_text