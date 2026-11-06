"""Abstract repository interface and default unconfigured implementation."""

from abc import ABC, abstractmethod
from typing import Optional

from app.core.exceptions import ServiceUnavailableException
from app.domain.user import UserDomain


class UserRepositoryInterface(ABC):
    """Abstract interface for user data retrieval.

    Decouples authentication business logic from physical database engines and ORMs.
    """

    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[UserDomain]:
        """Retrieve user domain entity by email address."""
        pass

    @abstractmethod
    async def get_by_id(self, user_id: int) -> Optional[UserDomain]:
        """Retrieve user domain entity by unique integer user identifier (UserId)."""
        pass


class UnconfiguredUserRepository(UserRepositoryInterface):
    """Default production repository prior to Phase 2 SQL Server integration.

    Guarantees that unconfigured live runs fail safely with 503 Service Unavailable,
    preventing any mock login bypass or unverified authentication in production.
    """

    async def get_by_email(self, email: str) -> Optional[UserDomain]:
        raise ServiceUnavailableException(
            "Database service is not configured or currently unavailable. Live login is not yet available."
        )

    async def get_by_id(self, user_id: int) -> Optional[UserDomain]:
        raise ServiceUnavailableException(
            "Database service is not configured or currently unavailable. Live login is not yet available."
        )
