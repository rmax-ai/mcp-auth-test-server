"""Comprehensive end-to-end flow coverage for the canonical auth surfaces."""

from __future__ import annotations

import pytest

from tests.flow_helpers import (
    bearer_headers,
    code_challenge,
    jsonrpc_payload,
    redirect_query,
)


@pytest.mark.asyncio
async def test_bearer_token_flow(client):
    initialize = await client.post(
        "/mcp/bearer-token",
        headers=bearer_headers(),
        json=jsonrpc_payload(request_id="e2e-bearer-init", method="initialize"),
    )
    ping = await client.post(
        "/mcp/bearer-token",
        headers=bearer_headers(),
        json=jsonrpc_payload(
            request_id="e2e-bearer-ping",
            method="tools/call",
            params={"name": "ping", "arguments": {}},
        ),
    )

    assert initialize.status_code == 200
    assert "static mock bearer token" in initialize.json()["result"]["instructions"]
    assert ping.status_code == 200
    assert ping.json()["result"]["structuredContent"] == {"pong": True}


@pytest.mark.asyncio
async def test_oauth_auth_code_flow(client):
    metadata = await client.get("/.well-known/oauth-authorization-server")
    register = await client.post(
        metadata.json()["registration_endpoint"].removeprefix("http://test"),
        json={
            "client_name": "Phase 10 Browser Client",
            "redirect_uris": ["https://client.example/phase-10/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": "mcp:read",
        },
    )
    registration = register.json()
    verifier = "phase-10-oauth-verifier"

    authorize = await client.get(
        metadata.json()["authorization_endpoint"].removeprefix("http://test"),
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": "https://client.example/phase-10/callback",
            "scope": "mcp:read",
            "state": "phase-10-state",
            "resource": "http://test/mcp/oauth",
            "code_challenge": code_challenge(verifier),
            "code_challenge_method": "S256",
            "auto_approve": "true",
        },
        follow_redirects=False,
    )
    authorization_code = redirect_query(authorize.headers["location"])["code"][0]

    token = await client.post(
        metadata.json()["token_endpoint"].removeprefix("http://test"),
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/phase-10/callback",
            "client_id": registration["client_id"],
            "code_verifier": verifier,
            "resource": "http://test/mcp/oauth",
        },
    )
    mcp = await client.post(
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
        json=jsonrpc_payload(request_id="e2e-oauth-init", method="initialize"),
    )

    assert metadata.status_code == 200
    assert register.status_code == 201
    assert authorize.status_code == 302
    assert token.status_code == 200
    assert token.json()["aud"] == "http://test/mcp/oauth"
    assert mcp.status_code == 200


@pytest.mark.asyncio
async def test_oauth_client_credentials_flow(client):
    register = await client.post(
        "/oauth/register",
        json={
            "client_name": "Phase 10 Service Client",
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
            "scope": "mcp:write",
        },
    )
    registration = register.json()
    token = await client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": registration["client_id"],
            "client_secret": registration["client_secret"],
            "scope": "mcp:write",
        },
    )
    mcp = await client.post(
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
        json=jsonrpc_payload(request_id="e2e-client-creds-init", method="initialize"),
    )

    assert register.status_code == 201
    assert token.status_code == 200
    assert token.json()["scope"] == "mcp:write"
    assert mcp.status_code == 200


@pytest.mark.asyncio
async def test_oauth_device_flow(client):
    authorize = await client.post(
        "/oauth/device/authorize",
        data={"client_id": "phase-11-device-client"},
    )
    verify = await client.post(
        "/oauth/device/verify/consent",
        data={"user_code": authorize.json()["user_code"], "decision": "approve"},
    )
    token = await client.post(
        "/oauth/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": "phase-11-device-client",
            "device_code": authorize.json()["device_code"],
        },
    )
    mcp = await client.post(
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
        json=jsonrpc_payload(request_id="e2e-device-init", method="initialize"),
    )

    assert authorize.status_code == 200
    assert verify.status_code == 200
    assert token.status_code == 200
    assert token.json()["aud"] == "http://test/mcp/oauth"
    assert mcp.status_code == 200


@pytest.mark.asyncio
async def test_dynamic_registration_flow(client):
    public_registration = await client.post(
        "/oauth/register",
        json={
            "client_name": "Phase 10 Public Client",
            "redirect_uris": ["https://client.example/phase-10/public/callback"],
        },
    )
    confidential_registration = await client.post(
        "/oauth/register",
        json={
            "client_name": "Phase 10 Confidential Client",
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
            "scope": "mcp:write",
        },
    )

    assert public_registration.status_code == 201
    assert public_registration.json()["grant_types"] == ["authorization_code"]
    assert public_registration.json()["token_endpoint_auth_method"] == "none"
    assert confidential_registration.status_code == 201
    assert confidential_registration.json()["grant_types"] == ["client_credentials"]
    assert confidential_registration.json()["client_secret"]
