"""Authentication API endpoints for CeylonGo."""

from fastapi import APIRouter, Depends, Request, status

from app.core.dependencies import get_auth_service
from app.core.exceptions import AuthenticationFailedException
from app.core.rate_limit import login_rate_limiter
from app.schemas.auth import ErrorResponse, LoginRequest, TokenResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def get_client_ip(request: Request) -> str:
    """Extract client IP address safely, preferring direct client host or first forwarded IP."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # Take first IP in chain
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials or inactive account"},
        422: {"description": "Request validation error"},
        429: {"model": ErrorResponse, "description": "Too many login attempts"},
        503: {"model": ErrorResponse, "description": "Database service unavailable"},
    },
    summary="Authenticate user and issue JWT access token",
    description="Authenticates Tourist, Vendor, or Admin credentials against database and returns a signed expiring JWT.",
)
async def login(
    credentials: LoginRequest,
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    """Validate user credentials, enforce rate limits, and generate JWT access token."""
    client_ip = get_client_ip(request)

    # 1. Enforce sliding window rate limit
    login_rate_limiter.check_rate_limit(client_ip)

    try:
        # 2. Perform authentication via AuthService
        response = await auth_service.authenticate(
            email=credentials.email,
            password=credentials.password,
        )
        return response
    except AuthenticationFailedException:
        # Record failed attempt against rate limiter
        login_rate_limiter.record_attempt(client_ip)
        raise
