"""Unit tests for Argon2id password verifier, reusable helper, and boundary handling."""

import pytest
from app.core.password import (
    Argon2PasswordVerifier,
    BcryptPasswordVerifier,
    hash_password,
    password_hash,
)


@pytest.mark.unit
def test_argon2_valid_password_verification():
    """Test standard Argon2id verification for matching and non-matching passwords."""
    verifier = Argon2PasswordVerifier()
    plain_pw = "ValidPassword123!"
    hashed = verifier.hash(plain_pw)

    assert hashed.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert verifier.verify(plain_pw, hashed) is True
    assert verifier.verify("WrongPassword", hashed) is False


@pytest.mark.unit
def test_argon2_passwords_exceeding_72_bytes_supported():
    """Test that passwords exceeding legacy bcrypt 72-byte limit are supported without truncation."""
    verifier = Argon2PasswordVerifier()

    # Passwords of 80, 150, and 250 characters must be handled without error or truncation
    long_pw_1 = "SecurePassphraseWithManyWordsThatEasilyExceedsTheOldBcrypt72ByteBoundary1234567890!"
    assert len(long_pw_1.encode("utf-8")) > 72

    hashed_long = verifier.hash(long_pw_1)
    assert verifier.verify(long_pw_1, hashed_long) is True
    assert verifier.verify(long_pw_1 + "extra", hashed_long) is False

    # Verify a password that differs only after byte 72 is NOT treated as matching
    long_pw_variant = long_pw_1[:-1] + "?"
    assert verifier.verify(long_pw_variant, hashed_long) is False


@pytest.mark.unit
def test_argon2_malformed_hash_handled_safely():
    """Test that corrupted, empty, or non-Argon2 hashes return False safely without raising 500."""
    verifier = Argon2PasswordVerifier()

    assert verifier.verify("AnyPassword", "malformed_hash_value") is False
    assert verifier.verify("AnyPassword", "$argon2id$corrupted$parameters$") is False
    assert verifier.verify("AnyPassword", "") is False
    assert verifier.verify("", "$argon2id$v=19$m=65536,t=3,p=4$somehash") is False
    assert verifier.verify("AnyPassword", None) is False


@pytest.mark.unit
def test_dummy_hash_verification():
    """Test simulated verification to reduce timing differences for nonexistent accounts."""
    verifier = Argon2PasswordVerifier()
    # Dummy verification must always return False
    assert verifier.verify_dummy("TestPassword") is False
    assert verifier.verify_dummy("") is False


@pytest.mark.unit
def test_reusable_hash_password_helper():
    """Test that the shared hash_password helper can be reused by registration."""
    plain_pw = "RegistrationPassword456!"
    hashed = hash_password(plain_pw)

    assert hashed.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert password_hash.verify(plain_pw, hashed) is True

    # Empty password must raise ValueError
    with pytest.raises(ValueError):
        hash_password("")


@pytest.mark.unit
def test_bcrypt_alias_backward_compatibility():
    """Verify legacy BcryptPasswordVerifier symbol points to Argon2PasswordVerifier."""
    assert BcryptPasswordVerifier is Argon2PasswordVerifier
