"""Unit tests for POST /api/auth/login endpoint."""

import pytest
from httpx import AsyncClient


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_success_tourist(client: AsyncClient):
    """Test successful login for Tourist role."""
    response = await client.post(
        "/api/auth/login",
        json={"email": "tourist@example.com", "password": "TouristPass123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 1800
    assert data["user"]["id"] == 1
    assert data["user"]["name"] == "Nimal Perera"
    assert data["user"]["email"] == "tourist@example.com"
    assert data["user"]["role"] == "Tourist"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_success_vendor(client: AsyncClient):
    """Test successful login for Vendor role."""
    response = await client.post(
        "/api/auth/login",
        json={"email": "vendor@example.com", "password": "VendorPass123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["id"] == 2
    assert data["user"]["name"] == "Sunil Homestay"
    assert data["user"]["role"] == "Vendor"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_success_admin(client: AsyncClient):
    """Test successful login for Admin role."""
    response = await client.post(
        "/api/auth/login",
        json={"email": "admin@example.com", "password": "AdminPass123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["id"] == 3
    assert data["user"]["name"] == "Kamal Admin"
    assert data["user"]["role"] == "Admin"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_invalid_password_returns_safe_401(client: AsyncClient):
    """Test that wrong password returns generic 401."""
    response = await client.post(
        "/api/auth/login",
        json={"email": "tourist@example.com", "password": "WrongPassword!"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}
    assert "Bearer" in response.headers.get("WWW-Authenticate", "")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_unknown_email_returns_safe_401(client: AsyncClient):
    """Test that nonexistent email returns identical generic 401."""
    response = await client.post(
        "/api/auth/login",
        json={"email": "nonexistent@example.com", "password": "AnyPassword123!"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_inactive_account_returns_safe_401(client: AsyncClient):
    """Test that inactive account returns identical safe 401 (Option A policy)."""
    response = await client.post(
        "/api/auth/login",
        json={"email": "inactive@example.com", "password": "InactivePass123!"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_missing_fields_returns_422(client: AsyncClient):
    """Test missing email or password triggers 422."""
    response = await client.post("/api/auth/login", json={"email": "tourist@example.com"})
    assert response.status_code == 422

    response2 = await client.post("/api/auth/login", json={"password": "Password123!"})
    assert response2.status_code == 422


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_invalid_email_format_returns_422(client: AsyncClient):
    """Test malformed email triggers RFC 5322 validation error."""
    response = await client.post(
        "/api/auth/login",
        json={"email": "not-a-valid-email", "password": "Password123!"},
    )
    assert response.status_code == 422


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_client_role_injection_rejected_422(client: AsyncClient):
    """Test extra fields like client-supplied 'role' are rejected by extra='forbid'."""
    response = await client.post(
        "/api/auth/login",
        json={
            "email": "tourist@example.com",
            "password": "TouristPass123!",
            "role": "Admin",  # Privilege injection attempt
        },
    )
    assert response.status_code == 422
    data = response.json()
    assert any("extra_forbidden" in str(err) for err in data.get("detail", []))


@pytest.mark.unit
@pytest.mark.asyncio
async def test_validation_error_never_exposes_password(client: AsyncClient):
    """Test that validation errors never echo the password string in the response body."""
    secret_pw = "SuperSecretPasswordThatMustNotBeLeaked"
    # Send empty string password to trigger min_length=1 validation error
    response = await client.post(
        "/api/auth/login",
        json={"email": "tourist@example.com", "password": ""},
    )
    assert response.status_code == 422
    body_text = response.text
    # Verify the secret password is not leaked anywhere in the response text
    assert secret_pw not in body_text

    # Also test an invalid payload containing the secret password with invalid type
    response2 = await client.post(
        "/api/auth/login",
        json={"email": "invalid-email", "password": secret_pw},
    )
    assert response2.status_code == 422
    assert secret_pw not in response2.text


@pytest.mark.unit
@pytest.mark.asyncio
async def test_rate_limiter_blocks_after_threshold_with_429(client: AsyncClient):
    """Test that consecutive failed logins trigger 429 Too Many Requests with Retry-After."""
    # Settings default is 5 attempts
    for _ in range(5):
        res = await client.post(
            "/api/auth/login",
            json={"email": "tourist@example.com", "password": "WrongPassword!"},
        )
        assert res.status_code == 401

    # 6th attempt should be blocked by rate limiter
    blocked_res = await client.post(
        "/api/auth/login",
        json={"email": "tourist@example.com", "password": "WrongPassword!"},
    )
    assert blocked_res.status_code == 429
    assert "Retry-After" in blocked_res.headers
    assert int(blocked_res.headers["Retry-After"]) > 0
    assert "Too many login attempts" in blocked_res.json()["detail"]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_cors_preflight_headers(client: AsyncClient):
    """Test that preflight OPTIONS request returns configured CORS headers for Angular origin."""
    response = await client.options(
        "/api/auth/login",
        headers={
            "Origin": "http://localhost:4200",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type,Authorization",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:4200"
    assert "POST" in response.headers.get("access-control-allow-methods", "")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_user_with_unknown_database_role_fails_safely(client: AsyncClient, mock_user_repo):
    """Test that a database record with an unknown role fails safely without issuing token."""
    from app.domain.user import UserDomain
    from tests.conftest import HASH_TOURIST

    # Insert user with an invalid/unknown role
    rogue_user = UserDomain(
        id=999,
        name="Rogue User",
        email="rogue@example.com",
        password_hash=HASH_TOURIST,
        role="SuperUser",  # Invalid role not in ALLOWED_ROLES
        is_active=True,
    )
    mock_user_repo.save_user(rogue_user)

    response = await client.post(
        "/api/auth/login",
        json={"email": "rogue@example.com", "password": "TouristPass123!"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_user_with_missing_role_fails_safely(client: AsyncClient, mock_user_repo):
    """Test that a user with no role assigned (role=None) fails safely with 401."""
    from app.domain.user import UserDomain
    from tests.conftest import HASH_TOURIST

    norole_user = UserDomain(
        id=998,
        name="No Role User",
        email="norole@example.com",
        password_hash=HASH_TOURIST,
        role=None,  # Missing role (e.g. no UserRoles row)
        is_active=True,
    )
    mock_user_repo.save_user(norole_user)

    response = await client.post(
        "/api/auth/login",
        json={"email": "norole@example.com", "password": "TouristPass123!"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}


@pytest.mark.unit
@pytest.mark.asyncio
async def test_validation_error_nested_extra_fields_never_echo_passwords(client: AsyncClient):
    """Test that unexpected extra fields and whole-body errors never echo plaintext passwords."""
    raw_password = "CriticalSecretPasswordToProtect"
    response = await client.post(
        "/api/auth/login",
        json={
            "email": "tourist@example.com",
            "password": raw_password,
            "nested_payload": {
                "sub_password": "AnotherSecretPassword",
                "count": 10,
            },
        },
    )
    assert response.status_code == 422
    response_text = response.text
    # Verify neither password appears in the error response body
    assert raw_password not in response_text
    assert "AnotherSecretPassword" not in response_text
    assert "[REDACTED]" in response_text
