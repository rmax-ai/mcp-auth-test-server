"""Tests for the unified OAuth client-credentials flow."""

import pytest


@pytest.mark.asyncio
async def test_client_credentials_token_exchange_returns_access_token(client):
    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "phase-6-service-client",
            "client_secret": "phase-6-service-secret",
            "scope": "mcp:write",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "access_token": response.json()["access_token"],
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "mcp:write",
        "aud": "http://test/mcp/oauth",
        "iss": "http://test",
    }


@pytest.mark.asyncio
async def test_client_credentials_token_exchange_rejects_invalid_client(client):
    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "phase-6-service-client",
            "client_secret": "wrong-secret",
        },
    )

    assert response.status_code == 401
    assert response.json() == {
        "error": "invalid_client",
        "error_description": "client credentials are invalid",
    }


@pytest.mark.asyncio
async def test_client_credentials_token_grants_mcp_access(client):
    token_response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "phase-6-service-client",
            "client_secret": "phase-6-service-secret",
        },
    )
    access_token = token_response.json()["access_token"]

    mcp_response = await client.post(
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"jsonrpc": "2.0", "id": "init-2l", "method": "initialize", "params": {}},
    )

    assert mcp_response.status_code == 200
    assert mcp_response.json()["result"]["serverInfo"]["name"] == "mcp-auth-test-server"


@pytest.mark.asyncio
async def test_oauth_endpoint_accepts_auth_code_and_client_credentials_tokens(client):
    auth_code_token_response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "phase-6-service-client",
            "client_secret": "phase-6-service-secret",
        },
    )

    response = await client.post(
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {auth_code_token_response.json()['access_token']}"},
        json={"jsonrpc": "2.0", "id": "oauth-client-creds", "method": "initialize", "params": {}},
    )

    assert response.status_code == 200
