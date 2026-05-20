"""Tests for the bearer-token-protected MCP endpoint."""

import pytest

from mcp_auth_test_server.auth.bearer import BEARER_TOKEN_ENV_VAR, DEFAULT_BEARER_TOKEN


def _bearer_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_initialize_requires_valid_bearer_token(client):
    response = await client.post(
        "/mcp/bearer-token",
        headers=_bearer_headers(DEFAULT_BEARER_TOKEN),
        json={"jsonrpc": "2.0", "id": "init-1", "method": "initialize", "params": {}},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["result"]["serverInfo"]["name"] == "mcp-auth-test-server"
    assert data["result"]["instructions"] == "This endpoint requires a static mock bearer token."


@pytest.mark.asyncio
async def test_missing_authorization_header_returns_401(client):
    response = await client.post(
        "/mcp/bearer-token",
        json={"jsonrpc": "2.0", "id": "init-2", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing Authorization header"}
    assert response.headers["WWW-Authenticate"] == (
        'Bearer realm="mcp-auth-test-server", '
        'error="invalid_request", '
        'error_description="Missing Authorization header"'
    )


@pytest.mark.asyncio
async def test_invalid_token_returns_401_with_invalid_token_challenge(client):
    response = await client.post(
        "/mcp/bearer-token",
        headers=_bearer_headers("wrong-token"),
        json={"jsonrpc": "2.0", "id": "init-3", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Bearer token is invalid"}
    assert 'error="invalid_token"' in response.headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_non_bearer_authorization_header_returns_401(client):
    response = await client.post(
        "/mcp/bearer-token",
        headers={"Authorization": "Basic abc123"},
        json={"jsonrpc": "2.0", "id": "init-4", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Authorization header must use Bearer token auth"}
    assert 'error="invalid_request"' in response.headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_bearer_token_can_be_configured_with_env_override(client, monkeypatch):
    monkeypatch.setenv(BEARER_TOKEN_ENV_VAR, "phase-3-custom-token")

    rejected = await client.post(
        "/mcp/bearer-token",
        headers=_bearer_headers(DEFAULT_BEARER_TOKEN),
        json={"jsonrpc": "2.0", "id": "init-5a", "method": "initialize", "params": {}},
    )
    accepted = await client.post(
        "/mcp/bearer-token",
        headers=_bearer_headers("phase-3-custom-token"),
        json={"jsonrpc": "2.0", "id": "init-5b", "method": "initialize", "params": {}},
    )

    assert rejected.status_code == 401
    assert accepted.status_code == 200
