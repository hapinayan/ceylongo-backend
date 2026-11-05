"""Pytest fixtures and test environment configuration."""

import os

# Set required test environment configuration before any app or settings imports
os.environ.setdefault(
    "SECRET_KEY",
    "test-environment-secret-key-minimum-32-characters-long-strictly-for-tests",
)
os.environ.setdefault("ALGORITHM", "HS256")

import pytest
import pytest_asyncio
from typing import AsyncGenerator, Dict, Optional
from httpx import ASGITransport, AsyncClient

from app.core.dependencies import get_user_repository
from app.core.rate_limit import login_rate_limiter
from app.domain.user import UserDomain
from app.main import app
from app.repositories.base_user_repository import UserRepositoryInterface

# Pre-computed bcrypt hashes for fast deterministic test execution without dynamic CPU overhead
HASH_TOURIST = "$2b$04$m5O9APjSIjd8kp3LZVDo4OzWo9Q/ZPXyimA47HP3Nj9Bs2ikOdB/q"   # TouristPass123!
HASH_VENDOR  = "$2b$04$tGHlmgOQ65lZpqOTJuP3RO0U24BPcJvv1yechxg/WUcvitoyRJknS"   # VendorPass123!
HASH_ADMIN   = "$2b$04$o.w4g0BcYgmoqi/BYQDKUOiBzX5Z7uxUa5GQ4tpOLO1/khiJtwpjm"   # AdminPass123!
HASH_INACTIVE = "$2b$04$wbbNwI/mB.PNpUWyHKLf.eS4K50jZHhOXy/j4H44lZbn6Rbl0VvE6"  # InactivePass123!


class MockUserRepository(UserRepositoryInterface):
    """In-memory user repository strictly for unit test isolation.

    Contains NO production bypasses and is only wired via test dependency overrides.
    """

    def __init__(self):
        self._users_by_email: Dict[str, UserDomain] = {}
        self._users_by_id: Dict[str, UserDomain] = {}
        self._seed_data()

    def _seed_data(self):
        # 1. Active Tourist
        tourist = UserDomain(
            id="usr-tourist-001",
            name="Nimal Perera",
            email="tourist@example.com",
            password_hash=HASH_TOURIST,
            role="Tourist",
            is_active=True,
        )
        # 2. Active Vendor
        vendor = UserDomain(
            id="usr-vendor-001",
            name="Sunil Homestay",
            email="vendor@example.com",
            password_hash=HASH_VENDOR,
            role="Vendor",
            is_active=True,
        )
        # 3. Active Admin
        admin = UserDomain(
            id="usr-admin-001",
            name="Kamal Admin",
            email="admin@example.com",
            password_hash=HASH_ADMIN,
            role="Admin",
            is_active=True,
        )
        # 4. Inactive Tourist (Disabled account)
        inactive = UserDomain(
            id="usr-inactive-001",
            name="Disabled Tourist",
            email="inactive@example.com",
            password_hash=HASH_INACTIVE,
            role="Tourist",
            is_active=False,
        )

        for u in [tourist, vendor, admin, inactive]:
            self.save_user(u)

    def save_user(self, user: UserDomain) -> None:
        """Add or update a user entity in the test repository."""
        self._users_by_email[user.email.lower()] = user
        self._users_by_id[user.id] = user

    def delete_user(self, user_id: str) -> None:
        """Remove a user entity by ID to simulate account deletion."""
        if user_id in self._users_by_id:
            user = self._users_by_id.pop(user_id)
            self._users_by_email.pop(user.email.lower(), None)

    async def get_by_email(self, email: str) -> Optional[UserDomain]:
        return self._users_by_email.get(email.lower())

    async def get_by_id(self, user_id: str) -> Optional[UserDomain]:
        return self._users_by_id.get(user_id)


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Ensure rate limiter storage is cleared before each test."""
    login_rate_limiter.reset()
    yield
    login_rate_limiter.reset()


@pytest.fixture
def mock_user_repo() -> MockUserRepository:
    """Fixture providing a fresh mock repository."""
    return MockUserRepository()


@pytest_asyncio.fixture
async def client(mock_user_repo: MockUserRepository) -> AsyncGenerator[AsyncClient, None]:
    """Async test client with mock user repository dependency override."""
    app.dependency_overrides[get_user_repository] = lambda: mock_user_repo
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def unconfigured_client() -> AsyncGenerator[AsyncClient, None]:
    """Async test client WITHOUT overrides, simulating default unconfigured production wiring."""
    app.dependency_overrides.clear()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
