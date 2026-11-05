"""JWT token generation and verification utilities."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, PyJWTError

from app.core.config import settings
from app.core.exceptions import AuthenticationFailedException


def create_access_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed JWT access token.

    Contains minimal claims: 'sub', 'iat', and 'exp'.
    Email, roles, and personal data are omitted from the token payload.
    """
    if not subject or not str(subject).strip():
        raise ValueError("JWT subject ('sub') must be a non-empty string.")

    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": str(subject).strip(),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a signed JWT access token.

    Enforces algorithm verification against settings.ALGORITHM and requires 'sub', 'iat', and 'exp'.
    Rejects malformed, tampered, or unsupported claims safely.
    """
    if not token or not isinstance(token, str):
        raise AuthenticationFailedException("Could not validate credentials: empty or invalid token")

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={
                "require": ["sub", "iat", "exp"],
                "verify_sub": True,
                "verify_iat": True,
                "verify_exp": True,
            },
        )

        # Verify subject claim is a non-empty string
        sub = payload.get("sub")
        if not sub or not isinstance(sub, str) or not sub.strip():
            raise AuthenticationFailedException("Could not validate credentials: invalid subject")

        # Verify timestamps are valid numbers
        exp = payload.get("exp")
        iat = payload.get("iat")
        if not isinstance(exp, (int, float)) or not isinstance(iat, (int, float)):
            raise AuthenticationFailedException("Could not validate credentials: invalid timestamp claims")

        return payload
    except ExpiredSignatureError:
        raise AuthenticationFailedException("Token has expired")
    except (InvalidTokenError, PyJWTError):
        raise AuthenticationFailedException("Could not validate credentials")
