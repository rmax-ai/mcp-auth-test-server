"""Tests for the OAuth 2.0 authorization-code + PKCE flow."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _authorization_params(**overrides: str) -> dict[str, str]:
    verifier = overrides.pop("code_verifier", "phase-5-verifier")
    return {
        "response_type": "code",
        "client_id": "phase-5-public-client",
        "redirect_uri": "https://client.example/callback",
        "scope": "mcp:read",
        "state": "phase-5-state",
        "code_challenge": _code_challenge(verifier),
        "code_challenge_method": "S256",
        **overrides,
    }


def _redirect_query(location: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(location).query, keep_blank_values=True)


@pytest.mark.asyncio
async def test_authorize_requires_pkce_s256(client):
    response = await client.get(
        "/oauth/authorize",
        params=_authorization_params(code_challenge_method="plain"),
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_request",
        "error_description": "code_challenge_method must be S256",
    }


@pytest.mark.asyncio
async def test_authorize_renders_mock_consent_page(client):
    response = await client.get("/oauth/authorize", params=_authorization_params())

    assert response.status_code == 200
    assert "Mock OAuth Consent" in response.text
    assert "phase-5-public-client" in response.text
    assert 'action="/oauth/authorize/consent"' in response.text


@pytest.mark.asyncio
async def test_consent_denial_redirects_with_access_denied(client):
    response = await client.post(
        "/oauth/authorize/consent",
        data={**_authorization_params(), "decision": "deny"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    query = _redirect_query(response.headers["location"])
    assert query == {
        "error": ["access_denied"],
        "state": ["phase-5-state"],
    }


@pytest.mark.asyncio
async def test_full_auth_code_pkce_flow_allows_mcp_access(client):
    verifier = "phase-5-full-flow-verifier"

    authorize_response = await client.post(
        "/oauth/authorize/consent",
        data={**_authorization_params(code_verifier=verifier), "decision": "approve"},
        follow_redirects=False,
    )

    assert authorize_response.status_code == 302
    authorize_query = _redirect_query(authorize_response.headers["location"])
    authorization_code = authorize_query["code"][0]
    assert authorize_query["state"] == ["phase-5-state"]

    token_response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/callback",
            "client_id": "phase-5-public-client",
            "code_verifier": verifier,
        },
    )

    assert token_response.status_code == 200
    token_body = token_response.json()
    assert token_body["token_type"] == "Bearer"
    assert token_body["scope"] == "mcp:read"

    mcp_response = await client.post(
        "/mcp/oauth-v2-auth-code",
        headers={"Authorization": f"Bearer {token_body['access_token']}"},
        json={"jsonrpc": "2.0", "id": "init-oauth", "method": "initialize", "params": {}},
    )

    assert mcp_response.status_code == 200
    body = mcp_response.json()
    assert body["result"]["serverInfo"]["name"] == "mcp-auth-test-server"
    assert "authorization code + PKCE" in body["result"]["instructions"]
    assert "refresh_token" in token_body


@pytest.mark.asyncio
async def test_refresh_token_exchange_allows_mcp_access(client):
    verifier = "phase-5-refresh-flow-verifier"

    authorize_response = await client.get(
        "/oauth/authorize",
        params={**_authorization_params(code_verifier=verifier), "auto_approve": "true"},
        follow_redirects=False,
    )
    authorization_code = _redirect_query(authorize_response.headers["location"])["code"][0]

    token_response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/callback",
            "client_id": "phase-5-public-client",
            "code_verifier": verifier,
        },
    )
    refresh_token = token_response.json()["refresh_token"]

    refreshed = await client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "phase-5-public-client",
        },
    )

    assert refreshed.status_code == 200
    refreshed_body = refreshed.json()
    assert refreshed_body["scope"] == "mcp:read"
    assert refreshed_body["refresh_token"] == refresh_token

    mcp_response = await client.post(
        "/mcp/oauth-v2-auth-code",
        headers={"Authorization": f"Bearer {refreshed_body['access_token']}"},
        json={"jsonrpc": "2.0", "id": "refresh-oauth", "method": "initialize", "params": {}},
    )

    assert mcp_response.status_code == 200


@pytest.mark.asyncio
async def test_token_exchange_rejects_invalid_verifier_and_consumes_code(client):
    verifier = "phase-5-invalid-verifier"

    authorize_response = await client.get(
        "/oauth/authorize",
        params={**_authorization_params(code_verifier=verifier), "auto_approve": "true"},
        follow_redirects=False,
    )

    authorization_code = _redirect_query(authorize_response.headers["location"])["code"][0]

    rejected = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/callback",
            "client_id": "phase-5-public-client",
            "code_verifier": "wrong-verifier",
        },
    )
    reused = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/callback",
            "client_id": "phase-5-public-client",
            "code_verifier": verifier,
        },
    )

    assert rejected.status_code == 400
    assert rejected.json() == {
        "error": "invalid_grant",
        "error_description": "code_verifier does not match code_challenge",
    }
    assert reused.status_code == 400
    assert reused.json() == {
        "error": "invalid_grant",
        "error_description": "authorization code is invalid",
    }


@pytest.mark.asyncio
async def test_oauth_mcp_endpoint_requires_issued_access_token(client):
    response = await client.post(
        "/mcp/oauth-v2-auth-code",
        json={"jsonrpc": "2.0", "id": "missing", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing Authorization header"}
    assert response.headers["WWW-Authenticate"] == (
        'Bearer realm="mcp-auth-test-server", '
        'error="invalid_request", '
        'error_description="Missing Authorization header"'
    )


@pytest.mark.asyncio
async def test_auth_code_endpoint_rejects_client_credentials_token(client):
    token_response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "phase-6-service-client",
            "client_secret": "phase-6-service-secret",
        },
    )

    response = await client.post(
        "/mcp/oauth-v2-auth-code",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
        json={"jsonrpc": "2.0", "id": "wrong-grant", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Bearer token must be issued via authorization_code",
    }
