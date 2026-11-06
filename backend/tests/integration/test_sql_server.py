"""Isolated SQL Server 2022 integration tests.

Multi-Layer Safety Enforcements:
- Requires explicit opt-in via RUN_SQL_SERVER_INTEGRATION_TESTS=1.
- Requires non-empty TEST_DATABASE_URL targeting an isolated test database (CeylonGoDB_LoginTest).
- Strictly rejects targeting the application DATABASE_URL or CeylonGoDB.
- Never executes DDL (CREATE/DROP) or modifies schema.
- Cleans up only test-created records during fixture teardown, respecting foreign keys.
- Never displays credentials, password hashes, or JWT tokens in test logs or output.
"""

import os
import uuid
from typing import AsyncGenerator, Dict, List
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.dependencies import get_current_user, get_user_repository, require_roles
from app.core.password import hash_password
from app.core.rate_limit import login_rate_limiter
from app.domain.user import UserDomain
from app.main import app
from app.repositories.sql_user_repository import SqlAlchemyUserRepository

pytestmark = pytest.mark.integration


def get_verified_test_db_url() -> str:
    """Validate safety boundaries before allowing any connection to an integration test database."""
    opt_in = os.getenv("RUN_SQL_SERVER_INTEGRATION_TESTS", "").strip()
    if opt_in != "1":
        pytest.skip(
            "SQL Server integration tests skipped: RUN_SQL_SERVER_INTEGRATION_TESTS is not set to '1'."
        )

    test_db_url = os.getenv("TEST_DATABASE_URL", "").strip()
    if not test_db_url:
        pytest.skip(
            "SQL Server integration tests skipped: TEST_DATABASE_URL environment variable is not configured."
        )

    # Multi-layer safety: Verify test database is not identical to application DATABASE_URL
    app_db_url = (settings.DATABASE_URL or os.getenv("DATABASE_URL", "")).strip()
    if app_db_url and test_db_url == app_db_url:
        pytest.fail(
            "Safety violation: TEST_DATABASE_URL cannot be identical to DATABASE_URL. "
            "Integration tests must use a strictly isolated test database."
        )

    # Multi-layer safety: Prevent targeting the primary development database CeylonGoDB
    if "/CeylonGoDB?" in test_db_url or test_db_url.endswith("/CeylonGoDB"):
        pytest.fail(
            "Safety violation: TEST_DATABASE_URL targets 'CeylonGoDB'. "
            "Use a dedicated isolated test database (e.g. 'CeylonGoDB_LoginTest') to prevent modifying development data."
        )

    return test_db_url


@pytest.fixture(scope="module")
def test_db_engine():
    """Create a scoped SQLAlchemy engine for the verified isolated test database."""
    test_db_url = get_verified_test_db_url()

    try:
        engine = create_engine(test_db_url, pool_pre_ping=True)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        pytest.skip(f"SQL Server test database connection failed: {exc}")

    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def test_db_session_factory(test_db_engine):
    """Sessionmaker factory bound to the isolated test database engine."""
    return sessionmaker(
        bind=test_db_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )


@pytest.fixture
def seeded_sql_users(test_db_session_factory) -> Dict[str, Dict]:
    """Seed test-only users with Argon2id hashes, resolving RoleId by RoleName dynamically.

    Cleans up all created user records and role assignments in fixture teardown.
    """
    run_id = uuid.uuid4().hex[:8]
    created_user_ids: List[int] = []

    # 1. Resolve role IDs dynamically from dbo.Roles
    with test_db_session_factory() as session:
        roles_result = session.execute(text("SELECT RoleId, RoleName FROM dbo.Roles")).fetchall()
        role_map = {row[1]: row[0] for row in roles_result}

    for required_role in ["Tourist", "Vendor", "Admin"]:
        if required_role not in role_map:
            pytest.fail(f"Required role '{required_role}' not found in dbo.Roles table.")

    # 2. Test user specifications
    test_specs = {
        "tourist": {
            "email": f"sql_test_tourist_{run_id}@example.com",
            "password": "TouristSecurePassword123!",
            "name": "SQL Test Tourist",
            "role": "Tourist",
            "is_active": True,
        },
        "vendor": {
            "email": f"sql_test_vendor_{run_id}@example.com",
            "password": "VendorSecurePassword123!",
            "name": "SQL Test Vendor",
            "role": "Vendor",
            "is_active": True,
        },
        "admin": {
            "email": f"sql_test_admin_{run_id}@example.com",
            "password": "AdminSecurePassword123!",
            "name": "SQL Test Admin",
            "role": "Admin",
            "is_active": True,
        },
        "inactive": {
            "email": f"sql_test_inactive_{run_id}@example.com",
            "password": "InactiveSecurePassword123!",
            "name": "SQL Test Inactive User",
            "role": "Tourist",
            "is_active": False,
        },
        "missing_role": {
            "email": f"sql_test_norole_{run_id}@example.com",
            "password": "NoRoleSecurePassword123!",
            "name": "SQL Test No Role User",
            "role": None,  # Will not insert into dbo.UserRoles
            "is_active": True,
        },
    }

    # 3. Insert test users
    with test_db_session_factory() as session:
        for key, spec in test_specs.items():
            pw_hash = hash_password(spec["password"])
            insert_user_sql = text("""
                INSERT INTO dbo.Users (Email, PasswordHash, DisplayName, IsActive, CreatedAtUtc)
                OUTPUT INSERTED.UserId
                VALUES (:email, :hash, :name, :active, SYSUTCDATETIME())
            """)
            user_id = session.execute(
                insert_user_sql,
                {
                    "email": spec["email"],
                    "hash": pw_hash,
                    "name": spec["name"],
                    "active": spec["is_active"],
                },
            ).scalar()

            created_user_ids.append(user_id)
            spec["user_id"] = user_id

            # Insert role relationship if user has an assigned role
            if spec["role"] is not None:
                role_id = role_map[spec["role"]]
                insert_role_sql = text("""
                    INSERT INTO dbo.UserRoles (UserId, RoleId)
                    VALUES (:uid, :rid)
                """)
                session.execute(insert_role_sql, {"uid": user_id, "rid": role_id})

        session.commit()

    yield test_specs

    # 4. Clean up only records created by this run, respecting foreign key ordering
    if created_user_ids:
        with test_db_session_factory() as session:
            # Delete child records in UserRoles first
            for uid in created_user_ids:
                session.execute(text("DELETE FROM dbo.UserRoles WHERE UserId = :uid"), {"uid": uid})
            # Delete parent records in Users
            for uid in created_user_ids:
                session.execute(text("DELETE FROM dbo.Users WHERE UserId = :uid"), {"uid": uid})
            session.commit()


@pytest_asyncio.fixture
async def sql_client(test_db_session_factory) -> AsyncGenerator[AsyncClient, None]:
    """AsyncClient wired with SqlAlchemyUserRepository pointing to isolated test DB."""
    repo = SqlAlchemyUserRepository(test_db_session_factory)
    app.dependency_overrides[get_user_repository] = lambda: repo
    login_rate_limiter.reset()

    # Mount temporary protected verification endpoints if not present
    existing_paths = [route.path for route in app.routes]
    if "/api/test-protected/me" not in existing_paths:
        @app.get("/api/test-protected/me")
        async def protected_me(user: UserDomain = Depends(get_current_user)):
            return {"user_id": user.id, "email": user.email, "role": user.role}

        @app.get("/api/test-protected/admin")
        async def protected_admin(user: UserDomain = Depends(require_roles(["Admin"]))):
            return {"admin_verified": True, "user_id": user.id}

        @app.get("/api/test-protected/vendor-or-admin")
        async def protected_vendor_or_admin(user: UserDomain = Depends(require_roles(["Vendor", "Admin"]))):
            return {"vendor_or_admin_verified": True, "user_id": user.id}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.pop(get_user_repository, None)
    login_rate_limiter.reset()


@pytest.mark.asyncio
async def test_sql_user_repository_nonexistent_email(test_db_session_factory):
    """Verify SqlAlchemyUserRepository safely returns None for a nonexistent user in the test database."""
    repo = SqlAlchemyUserRepository(test_db_session_factory)
    user = await repo.get_by_email("nonexistent_test_user_xyz@example.com")
    assert user is None


@pytest.mark.asyncio
async def test_sql_user_repository_nonexistent_id(test_db_session_factory):
    """Verify SqlAlchemyUserRepository safely returns None for a nonexistent user ID in the test database."""
    repo = SqlAlchemyUserRepository(test_db_session_factory)
    user = await repo.get_by_id(999999999)
    assert user is None


@pytest.mark.asyncio
async def test_sql_login_success_tourist(sql_client: AsyncClient, seeded_sql_users: Dict):
    """Verify successful login for Tourist against real SQL Server and Argon2id hash."""
    user = seeded_sql_users["tourist"]
    response = await sql_client.post(
        "/api/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 1800
    assert data["user"]["id"] == user["user_id"]
    assert data["user"]["email"] == user["email"]
    assert data["user"]["role"] == "Tourist"


@pytest.mark.asyncio
async def test_sql_login_success_vendor(sql_client: AsyncClient, seeded_sql_users: Dict):
    """Verify successful login for Vendor against real SQL Server and Argon2id hash."""
    user = seeded_sql_users["vendor"]
    response = await sql_client.post(
        "/api/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["id"] == user["user_id"]
    assert data["user"]["role"] == "Vendor"


@pytest.mark.asyncio
async def test_sql_login_success_admin(sql_client: AsyncClient, seeded_sql_users: Dict):
    """Verify successful login for Admin against real SQL Server and Argon2id hash."""
    user = seeded_sql_users["admin"]
    response = await sql_client.post(
        "/api/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["id"] == user["user_id"]
    assert data["user"]["role"] == "Admin"


@pytest.mark.asyncio
async def test_sql_login_invalid_password_returns_safe_401(sql_client: AsyncClient, seeded_sql_users: Dict):
    """Verify wrong password against real SQL Server account returns safe 401."""
    user = seeded_sql_users["tourist"]
    response = await sql_client.post(
        "/api/auth/login",
        json={"email": user["email"], "password": "WrongPasswordXYZ!"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}


@pytest.mark.asyncio
async def test_sql_login_nonexistent_email_returns_safe_401(sql_client: AsyncClient):
    """Verify nonexistent email against real SQL Server database returns safe 401."""
    response = await sql_client.post(
        "/api/auth/login",
        json={"email": "nobody_exists_in_sql_db@example.com", "password": "AnyPassword123!"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}


@pytest.mark.asyncio
async def test_sql_login_inactive_account_returns_safe_401(sql_client: AsyncClient, seeded_sql_users: Dict):
    """Verify inactive account in SQL database returns safe 401 (Option A error policy)."""
    user = seeded_sql_users["inactive"]
    response = await sql_client.post(
        "/api/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}


@pytest.mark.asyncio
async def test_sql_login_missing_role_returns_safe_401(sql_client: AsyncClient, seeded_sql_users: Dict):
    """Verify user with missing role assignment in SQL Server returns safe 401."""
    user = seeded_sql_users["missing_role"]
    response = await sql_client.post(
        "/api/auth/login",
        json={"email": user["email"], "password": user["password"]},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}


@pytest.mark.asyncio
async def test_sql_jwt_protected_access_and_role_enforcement(sql_client: AsyncClient, seeded_sql_users: Dict):
    """Verify JWT issued from real SQL Server login can access protected endpoints and enforce roles."""
    tourist_user = seeded_sql_users["tourist"]
    admin_user = seeded_sql_users["admin"]
    vendor_user = seeded_sql_users["vendor"]

    # 1. Login Tourist and obtain token
    t_login = await sql_client.post(
        "/api/auth/login",
        json={"email": tourist_user["email"], "password": tourist_user["password"]},
    )
    assert t_login.status_code == 200
    tourist_token = t_login.json()["access_token"]

    # 2. Login Admin and obtain token
    a_login = await sql_client.post(
        "/api/auth/login",
        json={"email": admin_user["email"], "password": admin_user["password"]},
    )
    assert a_login.status_code == 200
    admin_token = a_login.json()["access_token"]

    # 3. Login Vendor and obtain token
    v_login = await sql_client.post(
        "/api/auth/login",
        json={"email": vendor_user["email"], "password": vendor_user["password"]},
    )
    assert v_login.status_code == 200
    vendor_token = v_login.json()["access_token"]

    # 4. Tourist accesses /api/test-protected/me -> 200
    res_me = await sql_client.get(
        "/api/test-protected/me",
        headers={"Authorization": f"Bearer {tourist_token}"},
    )
    assert res_me.status_code == 200
    assert res_me.json()["user_id"] == tourist_user["user_id"]
    assert res_me.json()["role"] == "Tourist"

    # 5. Tourist attempts to access admin endpoint -> 403 Forbidden
    res_tourist_admin = await sql_client.get(
        "/api/test-protected/admin",
        headers={"Authorization": f"Bearer {tourist_token}"},
    )
    assert res_tourist_admin.status_code == 403

    # 6. Admin accesses admin endpoint -> 200 OK
    res_admin_admin = await sql_client.get(
        "/api/test-protected/admin",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_admin_admin.status_code == 200
    assert res_admin_admin.json()["admin_verified"] is True

    # 7. Vendor accesses vendor-or-admin endpoint -> 200 OK
    res_vendor = await sql_client.get(
        "/api/test-protected/vendor-or-admin",
        headers={"Authorization": f"Bearer {vendor_token}"},
    )
    assert res_vendor.status_code == 200

    # 8. Tourist accesses vendor-or-admin endpoint -> 403 Forbidden
    res_tourist_vendor = await sql_client.get(
        "/api/test-protected/vendor-or-admin",
        headers={"Authorization": f"Bearer {tourist_token}"},
    )
    assert res_tourist_vendor.status_code == 403

    # 9. Tampered token -> 401 Unauthorized
    tampered_token = tourist_token[:-5] + "XXXXX"
    res_tampered = await sql_client.get(
        "/api/test-protected/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert res_tampered.status_code == 401

    # 10. Missing token -> 401 Unauthorized
    res_no_token = await sql_client.get("/api/test-protected/me")
    assert res_no_token.status_code == 401
