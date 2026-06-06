"""Tests for the OAuth 2.0 Device Authorization Grant (RFC 8628)."""

import pytest

DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


@pytest.mark.asyncio
async def test_device_authorize_returns_device_and_user_codes(client):
    response = await client.post(
        "/oauth/device/authorize",
        data={"client_id": "phase-11-device-client", "scope": "mcp:read"},
    )

    assert response.status_code == 200
    body = response.json()
    assert "device_code" in body
    assert "user_code" in body
    assert body["verification_uri"] == "http://test/oauth/device/verify"
    assert body["verification_uri_complete"].startswith(
        "http://test/oauth/device/verify?user_code="
    )


@pytest.mark.asyncio
async def test_device_authorize_rejects_unknown_client(client):
    response = await client.post(
        "/oauth/device/authorize",
        data={"client_id": "missing-client"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_client",
        "error_description": "client is not registered",
    }


@pytest.mark.asyncio
async def test_device_flow_token_exchange_requires_verification(client):
    authorize = await client.post(
        "/oauth/device/authorize",
        data={"client_id": "phase-11-device-client"},
    )

    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": DEVICE_CODE_GRANT_TYPE,
            "client_id": "phase-11-device-client",
            "device_code": authorize.json()["device_code"],
        },
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "authorization_pending",
        "error_description": "device code has not been verified yet",
    }


@pytest.mark.asyncio
async def test_full_device_flow_allows_mcp_access(client):
    authorize = await client.post(
        "/oauth/device/authorize",
        data={"client_id": "phase-11-device-client", "scope": "mcp:read"},
    )
    user_code = authorize.json()["user_code"]
    device_code = authorize.json()["device_code"]

    verify = await client.post(
        "/oauth/device/verify/consent",
        data={"user_code": user_code, "decision": "approve"},
    )
    token = await client.post(
        "/oauth/token",
        data={
            "grant_type": DEVICE_CODE_GRANT_TYPE,
            "client_id": "phase-11-device-client",
            "device_code": device_code,
        },
    )
    access_token = token.json()["access_token"]
    mcp = await client.post(
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"jsonrpc": "2.0", "id": "device-flow-init", "method": "initialize", "params": {}},
    )

    assert verify.status_code == 200
    assert "Device Verified" in verify.text
    assert token.status_code == 200
    assert token.json()["aud"] == "http://test/mcp/oauth"
    assert mcp.status_code == 200


@pytest.mark.asyncio
async def test_device_flow_refresh_token_preserves_oauth_access(client):
    authorize = await client.post(
        "/oauth/device/authorize",
        data={"client_id": "phase-11-device-client"},
    )
    await client.post(
        "/oauth/device/verify/consent",
        data={"user_code": authorize.json()["user_code"], "decision": "approve"},
    )
    token = await client.post(
        "/oauth/token",
        data={
            "grant_type": DEVICE_CODE_GRANT_TYPE,
            "client_id": "phase-11-device-client",
            "device_code": authorize.json()["device_code"],
        },
    )

    refreshed = await client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token.json()["refresh_token"],
            "client_id": "phase-11-device-client",
            "resource": "http://test/mcp/oauth",
        },
    )

    assert refreshed.status_code == 200
    assert refreshed.json()["aud"] == "http://test/mcp/oauth"


@pytest.mark.asyncio
async def test_device_flow_registration_supports_device_code_grant(client):
    response = await client.post(
        "/oauth/register",
        json={
            "client_name": "Registered Device Client",
            "grant_types": [DEVICE_CODE_GRANT_TYPE, "refresh_token"],
            "token_endpoint_auth_method": "none",
        },
    )

    assert response.status_code == 201
    assert DEVICE_CODE_GRANT_TYPE in response.json()["grant_types"]
