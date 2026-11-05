"""Unit tests for JWT security utilities, claim validation, and authorization dependencies."""

from datetime import datetime, timedelta, timezone
import jwt
import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.config import settings
from app.core.dependencies import get_current_user, get_user_repository, require_roles
from app.core.exceptions import AuthenticationFailedException
from app.core.security import create_access_token, decode_access_token
from app.domain.user import UserDomain
from tests.conftest import MockUserRepository


@pytest.mark.unit
def test_create_and_decode_access_token():
    """Test generating a token and decoding its claims."""
    token = create_access_token(subject="user-123", expires_delta=timedelta(minutes=10))
    payload = decode_access_token(token)
    assert payload["sub"] == "user-123"
    assert "iat" in payload
    assert "exp" in payload
    assert payload["exp"] > payload["iat"]


@pytest.mark.unit
def test_token_missing_required_claims_rejected():
    """Test that tokens missing 'sub', 'exp', or 'iat' are rejected."""
    now = int(datetime.now(timezone.utc).timestamp())

    # Missing sub
    bad_token_no_sub = jwt.encode({"iat": now, "exp": now + 600}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    with pytest.raises(AuthenticationFailedException):
        decode_access_token(bad_token_no_sub)

    # Missing exp
    bad_token_no_exp = jwt.encode({"sub": "u1", "iat": now}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    with pytest.raises(AuthenticationFailedException):
        decode_access_token(bad_token_no_exp)

    # Missing iat
    bad_token_no_iat = jwt.encode({"sub": "u1", "exp": now + 600}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    with pytest.raises(AuthenticationFailedException):
        decode_access_token(bad_token_no_iat)


@pytest.mark.unit
def test_token_with_empty_or_whitespace_subject_rejected():
    """Test that empty or whitespace 'sub' claims fail safely."""
    now = int(datetime.now(timezone.utc).timestamp())
    empty_sub_token = jwt.encode(
        {"sub": "   ", "iat": now, "exp": now + 600},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    with pytest.raises(AuthenticationFailedException):
        decode_access_token(empty_sub_token)


@pytest.mark.unit
def test_token_with_non_numeric_timestamps_rejected():
    """Test that malformed string timestamps in claims are rejected."""
    now = int(datetime.now(timezone.utc).timestamp())
    malformed_exp_token = jwt.encode(
        {"sub": "u1", "iat": now, "exp": "not-a-timestamp"},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    with pytest.raises(AuthenticationFailedException):
        decode_access_token(malformed_exp_token)


@pytest.mark.unit
def test_unsupported_algorithm_rejected():
    """Test that tokens signed with unconfigured algorithms (including 'none') are rejected."""
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {"sub": "user-123", "iat": now, "exp": now + 600}

    # Algorithm 'none' attack attempt
    none_token = jwt.encode(payload, key="", algorithm="none")
    with pytest.raises(AuthenticationFailedException):
        decode_access_token(none_token)

    # Algorithm mismatch attempt (e.g. HS384 when HS256 is expected)
    mismatched_token = jwt.encode(payload, key=settings.SECRET_KEY, algorithm="HS384")
    with pytest.raises(AuthenticationFailedException):
        decode_access_token(mismatched_token)


@pytest.mark.unit
def test_expired_token_rejected():
    """Test that expired token raises AuthenticationFailedException."""
    expired_token = create_access_token(subject="user-123", expires_delta=timedelta(seconds=-10))
    with pytest.raises(AuthenticationFailedException) as exc_info:
        decode_access_token(expired_token)
    assert "expired" in str(exc_info.value).lower()


@pytest.mark.unit
def test_tampered_token_rejected():
    """Test that modifying token signature or payload causes rejection."""
    token = create_access_token(subject="user-123")
    tampered_token = token[:-5] + "XXXXX"
    with pytest.raises(AuthenticationFailedException):
        decode_access_token(tampered_token)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_reusable_role_dependencies(mock_user_repo: MockUserRepository):
    """Test require_roles dependency with allowed and denied access."""
    test_app = FastAPI()

    @test_app.get("/admin-only")
    async def admin_endpoint(user: UserDomain = Depends(require_roles(["Admin"]))):
        return {"msg": f"Welcome Admin {user.name}"}

    @test_app.get("/vendor-or-admin")
    async def vendor_endpoint(user: UserDomain = Depends(require_roles(["Vendor", "Admin"]))):
        return {"msg": f"Welcome Partner {user.name}"}

    test_app.dependency_overrides[get_user_repository] = lambda: mock_user_repo

    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        admin_token = create_access_token(subject="usr-admin-001")
        vendor_token = create_access_token(subject="usr-vendor-001")
        tourist_token = create_access_token(subject="usr-tourist-001")

        # Admin accesses admin-only -> 200
        res1 = await ac.get("/admin-only", headers={"Authorization": f"Bearer {admin_token}"})
        assert res1.status_code == 200

        # Vendor accesses admin-only -> 403 Forbidden
        res2 = await ac.get("/admin-only", headers={"Authorization": f"Bearer {vendor_token}"})
        assert res2.status_code == 403

        # Tourist accesses admin-only -> 403 Forbidden
        res3 = await ac.get("/admin-only", headers={"Authorization": f"Bearer {tourist_token}"})
        assert res3.status_code == 403

        # Vendor accesses vendor-or-admin -> 200
        res4 = await ac.get("/vendor-or-admin", headers={"Authorization": f"Bearer {vendor_token}"})
        assert res4.status_code == 200

        # Unauthenticated request -> 401 Unauthorized
        res5 = await ac.get("/admin-only")
        assert res5.status_code == 401


@pytest.mark.unit
@pytest.mark.asyncio
async def test_account_deactivation_after_token_issuance(mock_user_repo: MockUserRepository):
    """Test that deactivating an account immediately denies access on next request even if JWT is valid."""
    test_app = FastAPI()

    @test_app.get("/profile")
    async def profile_endpoint(user: UserDomain = Depends(get_current_user)):
        return {"name": user.name}

    test_app.dependency_overrides[get_user_repository] = lambda: mock_user_repo

    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        tourist_token = create_access_token(subject="usr-tourist-001")

        # 1. Active user -> 200
        res1 = await ac.get("/profile", headers={"Authorization": f"Bearer {tourist_token}"})
        assert res1.status_code == 200

        # 2. Deactivate user in repository
        tourist = await mock_user_repo.get_by_id("usr-tourist-001")
        assert tourist is not None
        tourist.is_active = False
        mock_user_repo.save_user(tourist)

        # 3. Same token should now be rejected immediately with 401
        res2 = await ac.get("/profile", headers={"Authorization": f"Bearer {tourist_token}"})
        assert res2.status_code == 401
        assert "inactive" in res2.json()["detail"].lower()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_account_deletion_after_token_issuance(mock_user_repo: MockUserRepository):
    """Test that deleting a user immediately denies access on next request."""
    test_app = FastAPI()

    @test_app.get("/profile")
    async def profile_endpoint(user: UserDomain = Depends(get_current_user)):
        return {"name": user.name}

    test_app.dependency_overrides[get_user_repository] = lambda: mock_user_repo

    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        vendor_token = create_access_token(subject="usr-vendor-001")

        # 1. Valid user -> 200
        res1 = await ac.get("/profile", headers={"Authorization": f"Bearer {vendor_token}"})
        assert res1.status_code == 200

        # 2. Delete user in repository
        mock_user_repo.delete_user("usr-vendor-001")

        # 3. Same token rejected immediately with 401
        res2 = await ac.get("/profile", headers={"Authorization": f"Bearer {vendor_token}"})
        assert res2.status_code == 401


@pytest.mark.unit
@pytest.mark.asyncio
async def test_role_change_after_token_issuance(mock_user_repo: MockUserRepository):
    """Test that role demotion in database immediately revokes permission on next request."""
    test_app = FastAPI()

    @test_app.get("/admin-only")
    async def admin_endpoint(user: UserDomain = Depends(require_roles(["Admin"]))):
        return {"msg": "Admin area"}

    test_app.dependency_overrides[get_user_repository] = lambda: mock_user_repo

    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        admin_token = create_access_token(subject="usr-admin-001")

        # 1. Active Admin -> 200
        res1 = await ac.get("/admin-only", headers={"Authorization": f"Bearer {admin_token}"})
        assert res1.status_code == 200

        # 2. Demote Admin to Tourist in database
        admin = await mock_user_repo.get_by_id("usr-admin-001")
        assert admin is not None
        admin.role = "Tourist"
        mock_user_repo.save_user(admin)

        # 3. Same token now immediately rejected with 403 Forbidden
        res2 = await ac.get("/admin-only", headers={"Authorization": f"Bearer {admin_token}"})
        assert res2.status_code == 403
