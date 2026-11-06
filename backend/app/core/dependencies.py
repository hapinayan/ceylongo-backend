"""Reusable FastAPI dependencies for authentication and authorization."""

from typing import Callable, List, Optional
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.exceptions import (
    AuthenticationFailedException,
    InsufficientPermissionsException,
    ServiceUnavailableException,
)
from app.core.password import Argon2PasswordVerifier, PasswordVerifierInterface
from app.core.security import decode_access_token
from app.db.session import get_session_factory
from app.domain.user import UserDomain
from app.repositories.base_user_repository import (
    UnconfiguredUserRepository,
    UserRepositoryInterface,
)
from app.repositories.sql_user_repository import SqlAlchemyUserRepository
from app.services.auth_service import AuthService

# Permitted active roles in CeylonGo
ALLOWED_ROLES = {"Tourist", "Vendor", "Admin"}

# Bearer token extractor
http_bearer_scheme = HTTPBearer(auto_error=False)

# Singleton instances for default application wiring
_default_user_repository = UnconfiguredUserRepository()
_default_password_verifier = Argon2PasswordVerifier()


def get_user_repository() -> UserRepositoryInterface:
    """Dependency provider for user repository.

    - Returns SqlAlchemyUserRepository if DATABASE_URL is configured and engine initialized.
    - Otherwise returns UnconfiguredUserRepository, which safely raises ServiceUnavailableException (503).
    - In tests, this dependency is overridden using app.dependency_overrides[get_user_repository].
    """
    if settings.DATABASE_URL:
        factory = get_session_factory()
        if factory is not None:
            return SqlAlchemyUserRepository(factory)
    return _default_user_repository


def get_password_verifier() -> PasswordVerifierInterface:
    """Dependency provider for password verifier.

    Provides Argon2id verifier (pwdlib[argon2]) behind PasswordVerifierInterface.
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

    Security rules enforced:
    - Rejects missing, empty, or whitespace bearer credentials (401).
    - Catches invalid subject-to-integer conversions and returns safe 401 (never a 500).
    - Rejects deleted or inactive accounts (401).
    - Rejects missing or unknown roles directly in get_current_user (401), protecting
      all authenticated endpoints even if they do not explicitly invoke require_roles.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = decode_access_token(token)
    user_id_raw = payload.get("sub")
    if not user_id_raw or not str(user_id_raw).strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Safely convert sub string to integer UserId; catch conversion failures with 401 (never 500)
    try:
        user_id = int(str(user_id_raw).strip())
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await user_repository.get_by_id(user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Reject missing or unknown roles immediately in get_current_user
    if user.role is None or user.role not in ALLOWED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials: unauthorized account role",
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
        if current_user.role is None or current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role(s): {', '.join(allowed_roles)}",
            )
        return current_user

    return role_checker
