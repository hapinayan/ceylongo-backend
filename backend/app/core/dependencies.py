"""Reusable FastAPI dependencies for authentication and authorization."""

from typing import Callable, List
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.exceptions import (
    AuthenticationFailedException,
    InsufficientPermissionsException,
    ServiceUnavailableException,
)
from app.core.password import BcryptPasswordVerifier, PasswordVerifierInterface
from app.core.security import decode_access_token
from app.domain.user import UserDomain
from app.repositories.base_user_repository import (
    UnconfiguredUserRepository,
    UserRepositoryInterface,
)
from app.services.auth_service import AuthService

# Bearer token extractor
http_bearer_scheme = HTTPBearer(auto_error=False)

# Singleton instances for default application wiring
_default_user_repository = UnconfiguredUserRepository()
_default_password_verifier = BcryptPasswordVerifier()


def get_user_repository() -> UserRepositoryInterface:
    """Dependency provider for user repository.

    In production (prior to Phase 2 SQL Server integration), returns UnconfiguredUserRepository,
    which safely raises ServiceUnavailableException (503).
    In tests, this dependency is overridden using app.dependency_overrides[get_user_repository].
    """
    return _default_user_repository


def get_password_verifier() -> PasswordVerifierInterface:
    """Dependency provider for password verifier.

    Provides provisional Bcrypt verifier behind PasswordVerifierInterface.
    Allows easy replacement once the team standardizes on a final hashing algorithm.
    """
    return _default_password_verifier


def get_auth_service(
    user_repository: UserRepositoryInterface = Depends(get_user_repository),
    password_verifier: PasswordVerifierInterface = Depends(get_password_verifier),
) -> AuthService:
    """Dependency provider for AuthService."""
    return AuthService(
        user_repository=user_repository,
        password_verifier=password_verifier,
    )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(http_bearer_scheme),
    user_repository: UserRepositoryInterface = Depends(get_user_repository),
) -> UserDomain:
    """Validate Bearer JWT access token and retrieve current active user from database.

    Real-time database lookup ensures deactivated, deleted, or role-modified accounts
    are immediately denied access even if their token has not expired.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await user_repository.get_by_id(str(user_id))
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_roles(allowed_roles: List[str]) -> Callable:
    """Factory dependency enforcing role-based access control.

    Returns 403 Forbidden if user's verified database role is not in allowed_roles.
    """
    async def role_checker(
        current_user: UserDomain = Depends(get_current_user),
    ) -> UserDomain:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role(s): {', '.join(allowed_roles)}",
            )
        return current_user

    return role_checker
