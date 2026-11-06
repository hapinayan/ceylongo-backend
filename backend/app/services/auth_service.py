"""Authentication service business logic."""

from app.core.config import settings
from app.core.exceptions import AuthenticationFailedException
from app.core.password import PasswordVerifierInterface
from app.core.security import create_access_token
from app.repositories.base_user_repository import UserRepositoryInterface
from app.schemas.auth import TokenResponse, UserResponse

# Permitted active roles in CeylonGo. Derived strictly from trusted database records.
ALLOWED_ROLES = {"Tourist", "Vendor", "Admin"}


class AuthService:
    """Coordinates credential verification, account activity checks, and token generation."""

    def __init__(
        self,
        user_repository: UserRepositoryInterface,
        password_verifier: PasswordVerifierInterface,
    ):
        self.user_repository = user_repository
        self.password_verifier = password_verifier

    async def authenticate(self, email: str, password: str) -> TokenResponse:
        """Authenticate user by email and password.

        Applies Option A policy: returns identical 401 for unknown email, incorrect password,
        or inactive/disabled account to prevent account enumeration.
        """
        # NOTE ON PROVISIONAL EMAIL NORMALIZATION:
        # Applying .strip().lower() here is provisional pending agreement with the registration
        # module owner and Anushan's confirmed SQL Server collation (e.g. SQL_Latin1_General_CP1_CI_AS).
        normalized_email = email.strip().lower()

        user = await self.user_repository.get_by_email(normalized_email)
        if user is None:
            # Execute dummy verification to reduce timing differences for nonexistent accounts
            self.password_verifier.verify_dummy(password)
            raise AuthenticationFailedException("Invalid email or password")

        # Verify password against securely stored hash
        if not self.password_verifier.verify(password, user.password_hash):
            raise AuthenticationFailedException("Invalid email or password")

        # Inactive Account Option A: Reject with identical generic 401
        if not user.is_active:
            raise AuthenticationFailedException("Invalid email or password")

        # Reject missing, unknown, or ambiguous role mappings safely
        if user.role is None or user.role not in ALLOWED_ROLES:
            raise AuthenticationFailedException("Invalid email or password")

        # Generate signed, expiring JWT with minimal claims ('sub', 'iat', 'exp')
        access_token = create_access_token(subject=str(user.id))
        expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in,
            user=UserResponse(
                id=user.id,
                name=user.name,
                email=user.email,
                role=user.role,
            ),
        )
