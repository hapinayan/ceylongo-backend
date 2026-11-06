"""Unit tests verifying that unconfigured production repository fails safely with 503."""

import pytest
from httpx import AsyncClient


@pytest.mark.unit
@pytest.mark.asyncio
async def test_unconfigured_production_repository_returns_503(unconfigured_client: AsyncClient):
    """Test that default application wiring (no mock overrides) returns safe 503 Service Unavailable."""
    response = await unconfigured_client.post(
        "/api/auth/login",
        json={"email": "tourist@example.com", "password": "AnyPassword123!"},
    )
    assert response.status_code == 503
    data = response.json()
    assert "detail" in data
    assert "Database service is not configured" in data["detail"]
    assert "Live login is not yet available" in data["detail"]
