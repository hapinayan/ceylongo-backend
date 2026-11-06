"""Unit tests verifying application settings and security configuration fail-safes."""

import pytest
from pydantic import ValidationError
from app.core.config import Settings


@pytest.mark.unit
def test_missing_secret_key_fails_validation(monkeypatch):
    """Test that omitting SECRET_KEY raises a clear validation error without fallback."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)
    assert "SECRET_KEY" in str(exc_info.value)


@pytest.mark.unit
def test_short_secret_key_fails_validation(monkeypatch):
    """Test that a SECRET_KEY shorter than 32 characters is rejected."""
    monkeypatch.setenv("SECRET_KEY", "too-short-secret-key")
    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)
    assert "at least 32 characters" in str(exc_info.value)


@pytest.mark.unit
def test_unsupported_algorithm_fails_validation(monkeypatch):
    """Test that insecure or unsupported algorithms like 'none' are rejected on startup."""
    monkeypatch.setenv("SECRET_KEY", "valid-length-secret-key-that-is-at-least-32-chars")
    monkeypatch.setenv("ALGORITHM", "none")
    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)
    assert "Unsupported JWT signing algorithm" in str(exc_info.value)


@pytest.mark.unit
def test_valid_configuration_succeeds(monkeypatch):
    """Test that a valid 32+ char secret and HS256 algorithm load cleanly."""
    monkeypatch.setenv("SECRET_KEY", "valid-length-secret-key-that-is-at-least-32-chars")
    monkeypatch.setenv("ALGORITHM", "HS256")
    settings = Settings(_env_file=None)
    assert settings.SECRET_KEY == "valid-length-secret-key-that-is-at-least-32-chars"
    assert settings.ALGORITHM == "HS256"
