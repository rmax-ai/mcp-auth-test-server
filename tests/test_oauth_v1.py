"""Tests for the OAuth 1.0a-protected MCP endpoint."""

from __future__ import annotations

import base64
import hashlib
import hmac
from urllib.parse import quote

import pytest

from mcp_auth_test_server.auth.oauth_v1 import (
    DEFAULT_OAUTH1_CONSUMER_KEY,
    DEFAULT_OAUTH1_CONSUMER_SECRET,
)


def _percent_encode(value: str) -> str:
    return quote(value, safe="~")


def _build_oauth_v1_header(
    *,
    method: str = "POST",
    url: str = "http://test/mcp/oauth-v1",
    consumer_key: str = DEFAULT_OAUTH1_CONSUMER_KEY,
    consumer_secret: str = DEFAULT_OAUTH1_CONSUMER_SECRET,
    timestamp: str = "1760000000",
    nonce: str = "nonce-1",
    signature_method: str = "HMAC-SHA1",
) -> str:
    params = {
        "oauth_consumer_key": consumer_key,
        "oauth_nonce": nonce,
        "oauth_signature_method": signature_method,
        "oauth_timestamp": timestamp,
        "oauth_version": "1.0",
    }

    normalized = "&".join(
        f"{key}={value}"
        for key, value in sorted(
            (_percent_encode(key), _percent_encode(value)) for key, value in params.items()
        )
    )
    base_string = "&".join(
        [
            _percent_encode(method),
            _percent_encode(url),
            _percent_encode(normalized),
        ]
    )
    signing_key = f"{_percent_encode(consumer_secret)}&"
    signature = base64.b64encode(
        hmac.new(
            signing_key.encode("utf-8"),
            base_string.encode("utf-8"),
            hashlib.sha1,
        ).digest()
    ).decode("ascii")

    header_params = {
        **params,
        "oauth_signature": signature,
    }
    values = ", ".join(
        f'{key}="{_percent_encode(value)}"' for key, value in header_params.items()
    )
    return f"OAuth {values}"


@pytest.mark.asyncio
async def test_initialize_requires_valid_oauth_v1_signature(client, monkeypatch):
    monkeypatch.setattr("mcp_auth_test_server.auth.oauth_v1.time.time", lambda: 1760000000)

    response = await client.post(
        "/mcp/oauth-v1",
        headers={"Authorization": _build_oauth_v1_header()},
        json={"jsonrpc": "2.0", "id": "init-1", "method": "initialize", "params": {}},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["result"]["serverInfo"]["name"] == "mcp-auth-test-server"
    assert data["result"]["instructions"] == (
        "This endpoint requires an OAuth 1.0a Authorization header signed with HMAC-SHA1."
    )


@pytest.mark.asyncio
async def test_missing_authorization_header_returns_401(client):
    response = await client.post(
        "/mcp/oauth-v1",
        json={"jsonrpc": "2.0", "id": "init-2", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing Authorization header"}
    assert 'oauth_problem="parameter_absent"' in response.headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_invalid_signature_returns_401(client, monkeypatch):
    monkeypatch.setattr("mcp_auth_test_server.auth.oauth_v1.time.time", lambda: 1760000000)

    response = await client.post(
        "/mcp/oauth-v1",
        headers={"Authorization": _build_oauth_v1_header(consumer_secret="wrong-secret")},
        json={"jsonrpc": "2.0", "id": "init-3", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "oauth_signature is invalid"}
    assert 'oauth_problem="signature_invalid"' in response.headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_reused_nonce_returns_401(client, monkeypatch):
    monkeypatch.setattr("mcp_auth_test_server.auth.oauth_v1.time.time", lambda: 1760000000)
    headers = {"Authorization": _build_oauth_v1_header(nonce="replay-me")}

    first = await client.post(
        "/mcp/oauth-v1",
        headers=headers,
        json={"jsonrpc": "2.0", "id": "init-4a", "method": "initialize", "params": {}},
    )
    second = await client.post(
        "/mcp/oauth-v1",
        headers=headers,
        json={"jsonrpc": "2.0", "id": "init-4b", "method": "initialize", "params": {}},
    )

    assert first.status_code == 200
    assert second.status_code == 401
    assert second.json() == {"detail": "oauth_timestamp and oauth_nonce were already used"}
    assert 'oauth_problem="nonce_used"' in second.headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_stale_timestamp_returns_401(client, monkeypatch):
    monkeypatch.setattr("mcp_auth_test_server.auth.oauth_v1.time.time", lambda: 1760000000)

    response = await client.post(
        "/mcp/oauth-v1",
        headers={
            "Authorization": _build_oauth_v1_header(timestamp="1759999000", nonce="old-nonce")
        },
        json={"jsonrpc": "2.0", "id": "init-5", "method": "initialize", "params": {}},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "oauth_timestamp is outside the accepted clock skew"}
    assert 'oauth_problem="timestamp_refused"' in response.headers["WWW-Authenticate"]
