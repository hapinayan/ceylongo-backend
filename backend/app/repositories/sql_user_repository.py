"""Concrete SQL Server user repository implementing parameterized queries."""

from typing import Callable, Optional
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.domain.user import UserDomain
from app.repositories.base_user_repository import UserRepositoryInterface


class SqlAlchemyUserRepository(UserRepositoryInterface):
    """SQL Server repository implementation for CeylonGo identity schema.

    - Uses parameterized queries to eliminate SQL injection risks.
    - Dynamically queries RoleName from dbo.Roles via JOIN; never hardcodes RoleId.
    - Preserves missing RoleName as None (never str(None)).
    - Uses run_in_threadpool so blocking pyodbc driver calls do not block FastAPI's async event loop.
    - Automatically closes database sessions via context manager.
    """

    def __init__(self, session_factory: Callable[[], Session]):
        self._session_factory = session_factory

    def _sync_get_by_email(self, email: str) -> Optional[UserDomain]:
        query = text("""
            SELECT
                u.UserId,
                u.DisplayName,
                u.Email,
                u.PasswordHash,
                u.IsActive,
                r.RoleName
            FROM dbo.Users u
            LEFT JOIN dbo.UserRoles ur ON u.UserId = ur.UserId
            LEFT JOIN dbo.Roles r ON ur.RoleId = r.RoleId
            WHERE u.Email = :email
        """)
        with self._session_factory() as session:
            result = session.execute(query, {"email": email}).mappings().first()
            if result is None:
                return None
            return self._map_row_to_domain(result)

    def _sync_get_by_id(self, user_id: int) -> Optional[UserDomain]:
        query = text("""
            SELECT
                u.UserId,
                u.DisplayName,
                u.Email,
                u.PasswordHash,
                u.IsActive,
                r.RoleName
            FROM dbo.Users u
            LEFT JOIN dbo.UserRoles ur ON u.UserId = ur.UserId
            LEFT JOIN dbo.Roles r ON ur.RoleId = r.RoleId
            WHERE u.UserId = :user_id
        """)
        with self._session_factory() as session:
            result = session.execute(query, {"user_id": user_id}).mappings().first()
            if result is None:
                return None
            return self._map_row_to_domain(result)

    def _map_row_to_domain(self, row) -> UserDomain:
        raw_role = row["RoleName"]
        # Explicit rule: preserve missing RoleName as None; never convert via str(None)
        role = str(raw_role) if raw_role is not None else None

        return UserDomain(
            id=int(row["UserId"]),
            name=str(row["DisplayName"]),
            email=str(row["Email"]),
            password_hash=str(row["PasswordHash"]),
            role=role,
            is_active=bool(row["IsActive"]),
        )

    async def get_by_email(self, email: str) -> Optional[UserDomain]:
        return await run_in_threadpool(self._sync_get_by_email, email)

    async def get_by_id(self, user_id: int) -> Optional[UserDomain]:
        return await run_in_threadpool(self._sync_get_by_id, user_id)
