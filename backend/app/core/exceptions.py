"""Custom exceptions for CeylonGo authentication and security."""

from typing import Optional


class CeylonGoException(Exception):
    """Base exception for CeylonGo application."""
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class AuthenticationFailedException(CeylonGoException):
    """Raised when authentication fails due to invalid credentials or inactive account (Option A)."""
    def __init__(self, detail: str = "Invalid email or password"):
        super().__init__(detail)


class ServiceUnavailableException(CeylonGoException):
    """Raised when database or external infrastructure is unconfigured or unreachable."""
    def __init__(
        self,
        detail: str = "Database service is not configured or currently unavailable. Live login is not yet available.",
    ):
        super().__init__(detail)


class InsufficientPermissionsException(CeylonGoException):
    """Raised when an authenticated user does not have the required role."""
    def __init__(self, detail: str = "Insufficient permissions to access this resource"):
        super().__init__(detail)


class RateLimitExceededException(CeylonGoException):
    """Raised when request frequency exceeds allowed limits."""
    def __init__(self, retry_after: int, detail: Optional[str] = None):
        self.retry_after = retry_after
        detail_msg = detail or f"Too many login attempts. Please try again in {retry_after} seconds."
        super().__init__(detail_msg)
