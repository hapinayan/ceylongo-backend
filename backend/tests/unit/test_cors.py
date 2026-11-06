"""Unit tests for CORS configuration and preflight headers."""

import pytest
from httpx import AsyncClient


@pytest.mark.unit
@pytest.mark.asyncio
async def test_cors_preflight_allowed_origin(client: AsyncClient):
    """Test CORS preflight OPTIONS request from an allowed origin."""
    headers = {
        "Origin": "http://localhost:4200",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization, Content-Type, Accept",
    }
    response = await client.options("/api/auth/login", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:4200"
    allow_methods = response.headers.get("access-control-allow-methods", "")
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
        assert method in allow_methods
    allow_headers = response.headers.get("access-control-allow-headers", "")
    for header in ["authorization", "content-type", "accept"]:
        assert header in allow_headers.lower()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_cors_preflight_disallowed_origin(client: AsyncClient):
    """Test CORS preflight OPTIONS request from an unapproved origin."""
    headers = {
        "Origin": "http://malicious-site.com",
        "Access-Control-Request-Method": "POST",
    }
    response = await client.options("/api/auth/login", headers=headers)
    assert "access-control-allow-origin" not in response.headers
