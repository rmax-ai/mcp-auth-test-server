"""Tests for RFC 7591 dynamic client registration."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _redirect_query(location: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(location).query, keep_blank_values=True)


@pytest.mark.asyncio
async def test_register_public_client_supports_oauth_auth_code_flow(client):
    registration = await client.post(
        "/oauth/register",
        json={
            "client_name": "Phase 9 Browser Client",
            "redirect_uris": ["https://client.example/phase-9/callback"],
            "scope": "mcp:read",
        },
    )

    assert registration.status_code == 201
    registration_body = registration.json()
    assert registration_body["token_endpoint_auth_method"] == "none"
    assert registration_body["grant_types"] == ["authorization_code"]
    assert "client_secret" not in registration_body

    verifier = "phase-9-public-client-verifier"
    authorize_response = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": registration_body["client_id"],
            "redirect_uri": "https://client.example/phase-9/callback",
            "scope": "mcp:read",
            "state": "phase-9-state",
            "code_challenge": _code_challenge(verifier),
            "code_challenge_method": "S256",
            "auto_approve": "true",
        },
        follow_redirects=False,
    )

    assert authorize_response.status_code == 302
    authorization_code = _redirect_query(authorize_response.headers["location"])["code"][0]

    token_response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/phase-9/callback",
            "client_id": registration_body["client_id"],
            "code_verifier": verifier,
        },
    )

    assert token_response.status_code == 200
    assert token_response.json()["scope"] == "mcp:read"


@pytest.mark.asyncio
async def test_register_confidential_client_supports_client_credentials_flow(client):
    registration = await client.post(
        "/oauth/register",
        json={
            "client_name": "Phase 9 Service Client",
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["client_credentials"],
            "scope": "mcp:write",
        },
    )

    assert registration.status_code == 201
    registration_body = registration.json()
    assert registration_body["grant_types"] == ["client_credentials"]
    assert registration_body["response_types"] == []
    assert registration_body["client_secret_expires_at"] == 0

    token_response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": registration_body["client_id"],
            "client_secret": registration_body["client_secret"],
            "scope": "mcp:write",
        },
    )

    assert token_response.status_code == 200
    access_token = token_response.json()["access_token"]

    mcp_response = await client.post(
        "/mcp/oauth-v2-client-creds",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"jsonrpc": "2.0", "id": "phase-9-2l", "method": "initialize", "params": {}},
    )

    assert mcp_response.status_code == 200


@pytest.mark.asyncio
async def test_register_public_client_supports_oauth_v21_flow(client):
    registration = await client.post(
        "/oauth/register",
        json={
            "client_name": "Phase 9 OAuth 2.1 Client",
            "redirect_uris": ["https://client.example/phase-9/oauth-v21/callback"],
            "scope": "mcp:read",
        },
    )

    registered_client = registration.json()
    verifier = "phase-9-oauth-v21-verifier"

    authorize_response = await client.get(
        "/oauth-v21/authorize",
        params={
            "response_type": "code",
            "client_id": registered_client["client_id"],
            "redirect_uri": "https://client.example/phase-9/oauth-v21/callback",
            "scope": "mcp:read",
            "state": "phase-9-oauth-v21-state",
            "resource": "http://test/mcp/oauth-v21",
            "code_challenge": _code_challenge(verifier),
            "code_challenge_method": "S256",
            "auto_approve": "true",
        },
        follow_redirects=False,
    )

    assert authorize_response.status_code == 302
    authorization_code = _redirect_query(authorize_response.headers["location"])["code"][0]

    token_response = await client.post(
        "/oauth-v21/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/phase-9/oauth-v21/callback",
            "client_id": registered_client["client_id"],
            "code_verifier": verifier,
            "resource": "http://test/mcp/oauth-v21",
        },
    )

    assert token_response.status_code == 200
    assert token_response.json()["aud"] == "http://test/mcp/oauth-v21"


@pytest.mark.asyncio
async def test_registration_rejects_unsupported_auth_method(client):
    response = await client.post(
        "/oauth/register",
        json={"token_endpoint_auth_method": "client_secret_basic"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_client_metadata",
        "error_description": "token_endpoint_auth_method is not supported",
    }


@pytest.mark.asyncio
async def test_registration_rejects_public_client_credentials_client(client):
    response = await client.post(
        "/oauth/register",
        json={
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "none",
        },
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_client_metadata",
        "error_description": (
            "client_credentials requires token_endpoint_auth_method client_secret_post"
        ),
    }
