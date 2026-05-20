"""Tests for the OAuth 2.0 client-credentials flow."""

from __future__ import annotations

import base64
import hashlib

import pytest


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


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
        "/mcp/oauth-v2-client-creds",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"jsonrpc": "2.0", "id": "init-2l", "method": "initialize", "params": {}},
    )

    assert mcp_response.status_code == 200
    body = mcp_response.json()
    assert body["result"]["serverInfo"]["name"] == "mcp-auth-test-server"
    assert "client credentials" in body["result"]["instructions"]


@pytest.mark.asyncio
async def test_client_credentials_endpoint_rejects_auth_code_token(client):
    verifier = "phase-6-mismatch-verifier"
    authorize_response = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "phase-5-public-client",
            "redirect_uri": "https://client.example/callback",
            "scope": "mcp:read",
            "state": "phase-6-state",
            "code_challenge": _code_challenge(verifier),
            "code_challenge_method": "S256",
            "auto_approve": "true",
        },
        follow_redirects=False,
    )
    location = authorize_response.headers["location"]
    code = location.split("code=", maxsplit=1)[1].split("&", maxsplit=1)[0]

    token_response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example/callback",
            "client_id": "phase-5-public-client",
            "code_verifier": verifier,
        },
    )

    mcp_response = await client.post(
        "/mcp/oauth-v2-client-creds",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
        json={"jsonrpc": "2.0", "id": "wrong-grant", "method": "initialize", "params": {}},
    )

    assert mcp_response.status_code == 401
    assert mcp_response.json() == {
        "detail": "Bearer token must be issued via client_credentials",
    }
