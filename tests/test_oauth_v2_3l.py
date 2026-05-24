"""Tests for the unified OAuth authorization-code + PKCE flow."""

from __future__ import annotations

import base64
import hashlib
import logging
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
        "resource": "http://test/mcp/oauth",
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
async def test_authorize_requires_resource_parameter(client):
    params = _authorization_params()
    params.pop("resource")

    response = await client.get("/oauth/authorize", params=params)

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_target",
        "error_description": "resource is required",
    }


@pytest.mark.asyncio
async def test_authorize_rejects_implicit_grant(client):
    response = await client.get(
        "/oauth/authorize",
        params=_authorization_params(response_type="token"),
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "unsupported_response_type",
        "error_description": "implicit grant is not supported",
    }


@pytest.mark.asyncio
async def test_authorize_renders_mock_consent_page(client):
    response = await client.get("/oauth/authorize", params=_authorization_params())

    assert response.status_code == 200
    assert "Mock OAuth Consent" in response.text
    assert "phase-5-public-client" in response.text
    assert 'action="/oauth/authorize/consent"' in response.text


@pytest.mark.asyncio
async def test_consent_denial_redirects_with_access_denied_and_issuer(client):
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
        "iss": ["http://test"],
    }


@pytest.mark.asyncio
async def test_full_auth_code_pkce_flow_allows_mcp_access(client):
    verifier = "phase-5-full-flow-verifier"

    authorize_response = await client.post(
        "/oauth/authorize/consent",
        data={**_authorization_params(code_verifier=verifier), "decision": "approve"},
        follow_redirects=False,
    )

    authorize_query = _redirect_query(authorize_response.headers["location"])
    authorization_code = authorize_query["code"][0]

    token_response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/callback",
            "client_id": "phase-5-public-client",
            "code_verifier": verifier,
            "resource": "http://test/mcp/oauth",
        },
    )

    token_body = token_response.json()
    mcp_response = await client.post(
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {token_body['access_token']}"},
        json={"jsonrpc": "2.0", "id": "init-oauth", "method": "initialize", "params": {}},
    )

    assert authorize_response.status_code == 302
    assert authorize_query["iss"] == ["http://test"]
    assert token_response.status_code == 200
    assert token_body["token_type"] == "Bearer"
    assert token_body["scope"] == "mcp:read"
    assert token_body["aud"] == "http://test/mcp/oauth"
    assert token_body["iss"] == "http://test"
    assert "refresh_token" in token_body
    assert mcp_response.status_code == 200
    assert "OAuth bearer token" in mcp_response.json()["result"]["instructions"]


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
            "resource": "http://test/mcp/oauth",
        },
    )
    refresh_token = token_response.json()["refresh_token"]

    refreshed = await client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "phase-5-public-client",
            "resource": "http://test/mcp/oauth",
        },
    )

    refreshed_body = refreshed.json()
    mcp_response = await client.post(
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {refreshed_body['access_token']}"},
        json={"jsonrpc": "2.0", "id": "refresh-oauth", "method": "initialize", "params": {}},
    )

    assert refreshed.status_code == 200
    assert refreshed_body["scope"] == "mcp:read"
    assert refreshed_body["refresh_token"] == refresh_token
    assert refreshed_body["aud"] == "http://test/mcp/oauth"
    assert mcp_response.status_code == 200


@pytest.mark.asyncio
async def test_oauth_tool_call_and_token_issuance_are_logged(client, caplog):
    caplog.set_level(logging.INFO, logger="mcp_auth_test_server.audit")
    verifier = "phase-5-log-verifier"

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
            "resource": "http://test/mcp/oauth",
        },
    )
    access_token = token_response.json()["access_token"]

    mcp_response = await client.post(
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "jsonrpc": "2.0",
            "id": "oauth-log-1",
            "method": "tools/call",
            "params": {"name": "ping", "arguments": {}},
        },
    )

    assert token_response.status_code == 200
    assert mcp_response.status_code == 200
    assert any(
        "oauth token issued endpoint=/oauth/token client_id=phase-5-public-client "
        "grant_type=authorization_code"
        in record.message
        and "audience=http://test/mcp/oauth" in record.message
        for record in caplog.records
    )
    assert any(
        "mcp request endpoint=/mcp/oauth auth_scheme=oauth2 "
        "caller=phase-5-public-client client_id=phase-5-public-client"
        in record.message
        and "grant_type=authorization_code" in record.message
        for record in caplog.records
    )


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
            "resource": "http://test/mcp/oauth",
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
            "resource": "http://test/mcp/oauth",
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
        "/mcp/oauth",
        json={"jsonrpc": "2.0", "id": "missing", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing Authorization header"}
    assert (
        'resource_metadata="http://test/.well-known/oauth-protected-resource?'
        'resource=http%3A%2F%2Ftest%2Fmcp%2Foauth"'
    ) in response.headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_oauth_mcp_endpoint_rejects_static_bearer_token(client):
    response = await client.post(
        "/mcp/oauth",
        headers={"Authorization": "Bearer test-bearer-token"},
        json={"jsonrpc": "2.0", "id": "static-on-oauth", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Bearer token is invalid"}
