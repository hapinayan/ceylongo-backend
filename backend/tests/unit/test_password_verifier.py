"""Unit tests for replaceable password verifier and Bcrypt boundary handling."""

import pytest
from app.core.password import BcryptPasswordVerifier


@pytest.mark.unit
def test_bcrypt_valid_password_verification():
    """Test standard verification for matching password and hash."""
    verifier = BcryptPasswordVerifier()
    plain_pw = "ValidPassword123!"
    hashed = verifier.hash(plain_pw)

    assert verifier.verify(plain_pw, hashed) is True
    assert verifier.verify("WrongPassword", hashed) is False


@pytest.mark.unit
def test_bcrypt_72_byte_limit_no_silent_truncation():
    """Test that inputs exceeding bcrypt's 72-byte limit are rejected explicitly without silent truncation."""
    verifier = BcryptPasswordVerifier()

    # Create a 73-byte password
    long_password = "A" * 73
    assert len(long_password.encode("utf-8")) == 73

    # Attempting to hash >72 bytes must raise ValueError
    with pytest.raises(ValueError) as exc_info:
        verifier.hash(long_password)
    assert "exceeds bcrypt maximum length" in str(exc_info.value)
    assert "Silent truncation is forbidden" in str(exc_info.value)

    # Valid 72-byte password should succeed
    exact_72_password = "B" * 72
    hashed_72 = verifier.hash(exact_72_password)
    assert verifier.verify(exact_72_password, hashed_72) is True

    # Verifying a >72 byte password against any hash must return False safely without truncation
    assert verifier.verify(long_password, hashed_72) is False


@pytest.mark.unit
def test_bcrypt_malformed_hash_handled_safely():
    """Test that corrupted, empty, or non-bcrypt hashes return False without crashing."""
    verifier = BcryptPasswordVerifier()
    assert verifier.verify("AnyPassword", "malformed_hash_value") is False
    assert verifier.verify("AnyPassword", "") is False
    assert verifier.verify("", "$2b$12$somehash") is False


@pytest.mark.unit
def test_dummy_hash_verification():
    """Test simulated verification to reduce timing differences."""
    verifier = BcryptPasswordVerifier()
    # Dummy verification must always return False
    assert verifier.verify_dummy("TestPassword") is False
