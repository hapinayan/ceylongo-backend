"""Main FastAPI application entry point for CeylonGo."""

import logging
from typing import Any, Dict, List
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.auth import router as auth_router
from app.core.config import settings
from app.core.exceptions import (
    AuthenticationFailedException,
    InsufficientPermissionsException,
    RateLimitExceededException,
    ServiceUnavailableException,
)

logger = logging.getLogger("ceylongo.auth")


def _sanitize_validation_payload(val: Any) -> Any:
    """Recursively redact any value associated with a password key in error payload inputs."""
    if isinstance(val, dict):
        sanitized = {}
        for k, v in val.items():
            if "password" in str(k).lower():
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = _sanitize_validation_payload(v)
        return sanitized
    if isinstance(val, list):
        return [_sanitize_validation_payload(item) for item in val]
    return val


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version="0.1.0",
        description="Shared backend API foundation for CeylonGo Tourism Platform",
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
    )

    # 1. CORS Configuration (Restricted strictly to Angular origins and Bearer flow)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=False,  # Bearer authentication header does not require cookie credentials
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )

    # 2. Custom Exception Handlers

    @app.exception_handler(AuthenticationFailedException)
    async def authentication_failed_handler(request: Request, exc: AuthenticationFailedException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": exc.message},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(InsufficientPermissionsException)
    async def insufficient_permissions_handler(request: Request, exc: InsufficientPermissionsException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": exc.message},
        )

    @app.exception_handler(RateLimitExceededException)
    async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceededException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": exc.message},
            headers={"Retry-After": str(exc.retry_after)},
        )

    @app.exception_handler(ServiceUnavailableException)
    async def service_unavailable_handler(request: Request, exc: ServiceUnavailableException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": exc.message},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        """Sanitize validation errors to guarantee sensitive fields (passwords) are NEVER echoed back.

        Handles field-level errors, whole-body errors, and unexpected nested input structures.
        """
        sanitized_errors: List[Dict[str, Any]] = []
        for error in exc.errors():
            err_dict = dict(error)
            loc = err_dict.get("loc", ())

            # If the error location directly points to password, redact input completely
            if any("password" in str(part).lower() for part in loc):
                err_dict["input"] = "[REDACTED]"
            elif "input" in err_dict:
                # Recursively redact any nested password key in whole-body or unexpected field inputs
                err_dict["input"] = _sanitize_validation_payload(err_dict["input"])

            sanitized_errors.append(err_dict)

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": sanitized_errors},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Catch-all handler ensuring internal exceptions, SQL traces, or secrets are not leaked."""
        logger.error(f"Unhandled exception during request {request.method} {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred. Please try again later."},
        )

    # 3. Mount Routers
    app.include_router(auth_router)

    @app.get("/api/health", tags=["Health"], summary="Service health status")
    async def health_check() -> Dict[str, Any]:
        return {
            "status": "healthy",
            "service": "CeylonGo Backend",
            "database_configured": False,  # Indicates Phase 1 status
        }

    return app


app = create_app()
