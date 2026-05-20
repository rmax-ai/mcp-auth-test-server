"""Tests for OAuth discovery metadata endpoints."""

import pytest


@pytest.mark.asyncio
async def test_oauth_protected_resource_metadata_document(client):
    response = await client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    assert response.json() == {
        "resource": "http://test/mcp/bearer-token",
        "authorization_servers": [
            "http://test/.well-known/oauth-authorization-server",
        ],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp:read", "mcp:write"],
    }


@pytest.mark.asyncio
async def test_oauth_authorization_server_metadata_document(client):
    response = await client.get("/.well-known/oauth-authorization-server")

    assert response.status_code == 200
    assert response.json() == {
        "issuer": "http://test",
        "authorization_endpoint": "http://test/oauth/authorize",
        "token_endpoint": "http://test/oauth/token",
        "registration_endpoint": "http://test/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["mcp:read", "mcp:write"],
    }


@pytest.mark.asyncio
async def test_oauth_v21_protected_resource_metadata_document(client):
    response = await client.get(
        "/.well-known/oauth-protected-resource",
        params={"resource": "http://test/mcp/oauth-v21"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "resource": "http://test/mcp/oauth-v21",
        "authorization_servers": [
            "http://test/.well-known/oauth-authorization-server?resource=http%3A%2F%2Ftest%2Fmcp%2Foauth-v21",
        ],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp:read", "mcp:write"],
    }


@pytest.mark.asyncio
async def test_oauth_v21_authorization_server_metadata_document(client):
    response = await client.get(
        "/.well-known/oauth-authorization-server",
        params={"resource": "http://test/mcp/oauth-v21"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "issuer": "http://test",
        "authorization_endpoint": "http://test/oauth-v21/authorize",
        "token_endpoint": "http://test/oauth-v21/token",
        "registration_endpoint": "http://test/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "resource_indicators_supported": True,
        "scopes_supported": ["mcp:read", "mcp:write"],
    }
