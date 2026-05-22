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
        'error_description="Missing Authorization header", '
        'resource_metadata="http://test/.well-known/oauth-protected-resource"'
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
    assert (
        'resource_metadata="http://test/.well-known/oauth-protected-resource"'
        in response.headers["WWW-Authenticate"]
    )


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
    assert (
        'resource_metadata="http://test/.well-known/oauth-protected-resource"'
        in response.headers["WWW-Authenticate"]
    )


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


@pytest.mark.asyncio
async def test_mint_endpoint_issues_temporary_bearer_token(client):
    mint_response = await client.post("/mcp/bearer-token/mint")

    assert mint_response.status_code == 200
    mint_body = mint_response.json()
    assert "access_token" in mint_body
    assert mint_body["token_type"] == "Bearer"
    assert mint_body["expires_in"] == 300

    mcp_response = await client.post(
        "/mcp/bearer-token",
        headers=_bearer_headers(mint_body["access_token"]),
        json={"jsonrpc": "2.0", "id": "mint-init", "method": "initialize", "params": {}},
    )

    assert mcp_response.status_code == 200
    assert mcp_response.json()["result"]["serverInfo"]["name"] == "mcp-auth-test-server"


@pytest.mark.asyncio
async def test_minted_tokens_are_independent(client):
    first = await client.post("/mcp/bearer-token/mint")
    second = await client.post("/mcp/bearer-token/mint")

    assert first.json()["access_token"] != second.json()["access_token"]

    for mint_body in (first.json(), second.json()):
        mcp_response = await client.post(
            "/mcp/bearer-token",
            headers=_bearer_headers(mint_body["access_token"]),
            json={"jsonrpc": "2.0", "id": "mint-independent", "method": "ping", "params": {}},
        )
        assert mcp_response.status_code == 200


@pytest.mark.asyncio
async def test_static_token_still_works_alongside_minted_tokens(client):
    mint_response = await client.post("/mcp/bearer-token/mint")
    assert mint_response.status_code == 200

    static_response = await client.post(
        "/mcp/bearer-token",
        headers=_bearer_headers(DEFAULT_BEARER_TOKEN),
        json={"jsonrpc": "2.0", "id": "static-still-works", "method": "initialize", "params": {}},
    )
    assert static_response.status_code == 200
