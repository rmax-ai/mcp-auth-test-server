"""Tests for the OAuth 2.1 authorization-code + PKCE flow."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _oauth_v21_resource() -> str:
    return "http://test/mcp/oauth-v21"


def _authorization_params(**overrides: str) -> dict[str, str]:
    verifier = overrides.pop("code_verifier", "phase-7-verifier")
    return {
        "response_type": "code",
        "client_id": "phase-7-public-client",
        "redirect_uri": "https://client.example/oauth-v21/callback",
        "scope": "mcp:read",
        "state": "phase-7-state",
        "resource": _oauth_v21_resource(),
        "code_challenge": _code_challenge(verifier),
        "code_challenge_method": "S256",
        **overrides,
    }


def _redirect_query(location: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(location).query, keep_blank_values=True)


@pytest.mark.asyncio
async def test_authorize_rejects_plain_pkce(client):
    response = await client.get(
        "/oauth-v21/authorize",
        params=_authorization_params(code_challenge_method="plain"),
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_request",
        "error_description": "code_challenge_method must be S256",
    }


@pytest.mark.asyncio
async def test_authorize_requires_resource_parameter(client):
    params = _authorization_params()
    params.pop("resource")

    response = await client.get("/oauth-v21/authorize", params=params)

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_target",
        "error_description": "resource is required",
    }


@pytest.mark.asyncio
async def test_authorize_rejects_implicit_grant(client):
    response = await client.get(
        "/oauth-v21/authorize",
        params=_authorization_params(response_type="token"),
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "unsupported_response_type",
        "error_description": "implicit grant is not supported",
    }


@pytest.mark.asyncio
async def test_authorize_redirect_includes_issuer_parameter(client):
    response = await client.get(
        "/oauth-v21/authorize",
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
        "/oauth-v21/authorize",
        params={**_authorization_params(code_verifier=verifier), "auto_approve": "true"},
        follow_redirects=False,
    )
    authorization_code = _redirect_query(authorize_response.headers["location"])["code"][0]

    response = await client.post(
        "/oauth-v21/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/oauth-v21/callback",
            "client_id": "phase-7-public-client",
            "code_verifier": verifier,
            "resource": "http://test/mcp/oauth-v2-auth-code",
        },
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_target",
        "error_description": "resource is not supported",
    }


@pytest.mark.asyncio
async def test_full_oauth_v21_flow_allows_mcp_access(client):
    verifier = "phase-7-full-flow-verifier"

    authorize_response = await client.post(
        "/oauth-v21/authorize/consent",
        data={**_authorization_params(code_verifier=verifier), "decision": "approve"},
        follow_redirects=False,
    )

    assert authorize_response.status_code == 302
    authorize_query = _redirect_query(authorize_response.headers["location"])
    authorization_code = authorize_query["code"][0]
    assert authorize_query["iss"] == ["http://test"]

    token_response = await client.post(
        "/oauth-v21/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/oauth-v21/callback",
            "client_id": "phase-7-public-client",
            "code_verifier": verifier,
            "resource": _oauth_v21_resource(),
        },
    )

    assert token_response.status_code == 200
    token_body = token_response.json()
    assert token_body["token_type"] == "Bearer"
    assert token_body["scope"] == "mcp:read"
    assert token_body["aud"] == _oauth_v21_resource()
    assert token_body["iss"] == "http://test"
    assert "refresh_token" in token_body

    mcp_response = await client.post(
        "/mcp/oauth-v21",
        headers={"Authorization": f"Bearer {token_body['access_token']}"},
        json={"jsonrpc": "2.0", "id": "init-oauth-v21", "method": "initialize", "params": {}},
    )

    assert mcp_response.status_code == 200
    body = mcp_response.json()
    assert body["result"]["serverInfo"]["name"] == "mcp-auth-test-server"
    assert "OAuth 2.1 bearer token" in body["result"]["instructions"]


@pytest.mark.asyncio
async def test_refresh_token_exchange_preserves_oauth_v21_resource_access(client):
    verifier = "phase-7-refresh-flow-verifier"
    authorize_response = await client.get(
        "/oauth-v21/authorize",
        params={**_authorization_params(code_verifier=verifier), "auto_approve": "true"},
        follow_redirects=False,
    )
    authorization_code = _redirect_query(authorize_response.headers["location"])["code"][0]

    token_response = await client.post(
        "/oauth-v21/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/oauth-v21/callback",
            "client_id": "phase-7-public-client",
            "code_verifier": verifier,
            "resource": _oauth_v21_resource(),
        },
    )
    refresh_token = token_response.json()["refresh_token"]

    refreshed = await client.post(
        "/oauth-v21/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "phase-7-public-client",
        },
    )

    assert refreshed.status_code == 200
    refreshed_body = refreshed.json()
    assert refreshed_body["aud"] == _oauth_v21_resource()
    assert refreshed_body["iss"] == "http://test"
    assert refreshed_body["refresh_token"] == refresh_token

    mcp_response = await client.post(
        "/mcp/oauth-v21",
        headers={"Authorization": f"Bearer {refreshed_body['access_token']}"},
        json={"jsonrpc": "2.0", "id": "refresh-oauth-v21", "method": "initialize", "params": {}},
    )

    assert mcp_response.status_code == 200


@pytest.mark.asyncio
async def test_oauth_v21_mcp_endpoint_rejects_wrong_audience(client):
    verifier = "phase-7-wrong-audience-verifier"
    authorize_response = await client.get(
        "/oauth-v21/authorize",
        params={**_authorization_params(code_verifier=verifier), "auto_approve": "true"},
        follow_redirects=False,
    )
    authorization_code = _redirect_query(authorize_response.headers["location"])["code"][0]

    token_response = await client.post(
        "/oauth-v21/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/oauth-v21/callback",
            "client_id": "phase-7-public-client",
            "code_verifier": verifier,
            "resource": _oauth_v21_resource(),
        },
    )
    access_token = token_response.json()["access_token"]
    token_record = client.app_state["oauth_token_store"].get_access_token(access_token)
    token_record.audience = "http://test/mcp/other-resource"

    response = await client.post(
        "/mcp/oauth-v21",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"jsonrpc": "2.0", "id": "wrong-aud", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Bearer token audience does not match this protected resource",
    }
    assert (
        'resource_metadata="http://test/.well-known/oauth-protected-resource?'
        'resource=http%3A%2F%2Ftest%2Fmcp%2Foauth-v21"'
    ) in response.headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_oauth_v21_mcp_endpoint_rejects_wrong_issuer(client):
    verifier = "phase-7-wrong-issuer-verifier"
    authorize_response = await client.get(
        "/oauth-v21/authorize",
        params={**_authorization_params(code_verifier=verifier), "auto_approve": "true"},
        follow_redirects=False,
    )
    authorization_code = _redirect_query(authorize_response.headers["location"])["code"][0]

    token_response = await client.post(
        "/oauth-v21/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/oauth-v21/callback",
            "client_id": "phase-7-public-client",
            "code_verifier": verifier,
            "resource": _oauth_v21_resource(),
        },
    )
    access_token = token_response.json()["access_token"]
    token_record = client.app_state["oauth_token_store"].get_access_token(access_token)
    token_record.issuer = "http://wrong-issuer"

    response = await client.post(
        "/mcp/oauth-v21",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"jsonrpc": "2.0", "id": "wrong-iss", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Bearer token issuer is invalid",
    }
