"""Pydantic schemas for CeylonGo authentication requests and responses."""

import email_validator
from pydantic import BaseModel, ConfigDict, EmailStr, Field

# Disable network DNS MX lookups during login request validation.
# Login only requires syntax validation; external DNS lookups add latency and fail in sandboxed/offline environments.
email_validator.CHECK_DELIVERABILITY = False


class LoginRequest(BaseModel):
    """Incoming credentials for POST /api/auth/login.

    Strictly forbids unexpected fields (such as client-injected 'role').
    """
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=False,  # Passwords must not be trimmed
    )

    email: EmailStr = Field(
        ...,
        description="User registered email address",
        examples=["tourist@example.com"],
    )
    password: str = Field(
        ...,
        min_length=1,
        max_length=1024,
        description="Account password",
        repr=False,  # Exclude from default string representations to prevent logging
    )


class UserResponse(BaseModel):
    """User profile data returned upon successful authentication."""
    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="User database integer identifier (UserId)")
    name: str = Field(..., description="User full display name (DisplayName)")
    email: str = Field(..., description="User email address")
    role: str = Field(..., description="Verified database role: Tourist, Vendor, or Admin")


class TokenResponse(BaseModel):
    """OAuth2-compatible Bearer token response."""
    access_token: str = Field(..., description="Signed expiring JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token validity lifetime in seconds")
    user: UserResponse = Field(..., description="Authenticated user profile")


class ErrorResponse(BaseModel):
    """Standardized error envelope."""
    detail: str = Field(..., description="Sanitized error description")
