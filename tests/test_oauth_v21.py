"""Tests for OAuth 2.1-style behavior on the shared OAuth surface."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _oauth_resource() -> str:
    return "http://test/mcp/oauth"


def _authorization_params(**overrides: str) -> dict[str, str]:
    verifier = overrides.pop("code_verifier", "phase-7-verifier")
    return {
        "response_type": "code",
        "client_id": "phase-7-public-client",
        "redirect_uri": "https://client.example/oauth-v21/callback",
        "scope": "mcp:read",
        "state": "phase-7-state",
        "resource": _oauth_resource(),
        "code_challenge": _code_challenge(verifier),
        "code_challenge_method": "S256",
        **overrides,
    }


def _redirect_query(location: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(location).query, keep_blank_values=True)


@pytest.mark.asyncio
async def test_authorize_redirect_includes_issuer_parameter(client):
    response = await client.get(
        "/oauth/authorize",
        params={**_authorization_params(), "auto_approve": "true"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    query = _redirect_query(response.headers["location"])
    assert query["iss"] == ["http://test"]
    assert query["state"] == ["phase-7-state"]
    assert "code" in query


@pytest.mark.asyncio
async def test_token_exchange_requires_matching_resource(client):
    verifier = "phase-7-resource-verifier"
    authorize_response = await client.get(
        "/oauth/authorize",
        params={**_authorization_params(code_verifier=verifier), "auto_approve": "true"},
        follow_redirects=False,
    )
    authorization_code = _redirect_query(authorize_response.headers["location"])["code"][0]

    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/oauth-v21/callback",
            "client_id": "phase-7-public-client",
            "code_verifier": verifier,
            "resource": "http://test/mcp/other-resource",
        },
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_target",
        "error_description": "resource is not supported",
    }


@pytest.mark.asyncio
async def test_refresh_token_exchange_preserves_resource_and_issuer(client):
    verifier = "phase-7-refresh-flow-verifier"
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
            "redirect_uri": "https://client.example/oauth-v21/callback",
            "client_id": "phase-7-public-client",
            "code_verifier": verifier,
            "resource": _oauth_resource(),
        },
    )
    refresh_token = token_response.json()["refresh_token"]

    refreshed = await client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "phase-7-public-client",
            "resource": _oauth_resource(),
        },
    )

    assert refreshed.status_code == 200
    assert refreshed.json()["aud"] == _oauth_resource()
    assert refreshed.json()["iss"] == "http://test"
    assert refreshed.json()["refresh_token"] == refresh_token


@pytest.mark.asyncio
async def test_oauth_endpoint_rejects_wrong_audience(client):
    verifier = "phase-7-wrong-audience-verifier"
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
            "redirect_uri": "https://client.example/oauth-v21/callback",
            "client_id": "phase-7-public-client",
            "code_verifier": verifier,
            "resource": _oauth_resource(),
        },
    )
    access_token = token_response.json()["access_token"]
    token_record = client.app_state["oauth_token_store"].get_access_token(access_token)
    token_record.audience = "http://test/mcp/other-resource"

    response = await client.post(
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"jsonrpc": "2.0", "id": "wrong-aud", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Bearer token audience does not match this protected resource",
    }


@pytest.mark.asyncio
async def test_oauth_endpoint_rejects_wrong_issuer(client):
    verifier = "phase-7-wrong-issuer-verifier"
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
            "redirect_uri": "https://client.example/oauth-v21/callback",
            "client_id": "phase-7-public-client",
            "code_verifier": verifier,
            "resource": _oauth_resource(),
        },
    )
    access_token = token_response.json()["access_token"]
    token_record = client.app_state["oauth_token_store"].get_access_token(access_token)
    token_record.issuer = "http://wrong-issuer"

    response = await client.post(
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"jsonrpc": "2.0", "id": "wrong-iss", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Bearer token issuer is invalid"}
