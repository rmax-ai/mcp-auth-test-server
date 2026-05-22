"""Tests for OpenAPI spec and documentation UIs."""

import pytest


@pytest.mark.asyncio
async def test_openapi_spec_is_available(client):
    response = await client.get("/openapi.json")

    assert response.status_code == 200
    data = response.json()
    assert data["openapi"].startswith("3.")
    assert "/health" in data["paths"]
    assert "/mcp/no-auth" in data["paths"]


@pytest.mark.asyncio
async def test_swagger_ui_is_available(client):
    response = await client.get("/docs")

    assert response.status_code == 200
    assert "Swagger UI" in response.text
    assert "/openapi.json" in response.text


@pytest.mark.asyncio
async def test_redoc_ui_is_available(client):
    response = await client.get("/redoc")

    assert response.status_code == 200
    assert "<redoc" in response.text
    assert "/openapi.json" in response.text
