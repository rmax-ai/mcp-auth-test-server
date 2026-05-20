"""Shared protocol helpers for end-to-end auth flow tests and live checks."""

from __future__ import annotations

import base64
import hashlib
import hmac
from urllib.parse import parse_qs, quote, urlparse

from mcp_auth_test_server.auth.bearer import DEFAULT_BEARER_TOKEN
from mcp_auth_test_server.auth.oauth_v1 import (
    DEFAULT_OAUTH1_CONSUMER_KEY,
    DEFAULT_OAUTH1_CONSUMER_SECRET,
)


def jsonrpc_payload(
    *,
    request_id: str,
    method: str,
    params: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build a minimal JSON-RPC request body for MCP endpoints."""

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params or {},
    }


def code_challenge(verifier: str) -> str:
    """Return a PKCE S256 code challenge for a verifier."""

    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def redirect_query(location: str) -> dict[str, list[str]]:
    """Parse the query string from an OAuth redirect URI."""

    return parse_qs(urlparse(location).query, keep_blank_values=True)


def bearer_headers(token: str = DEFAULT_BEARER_TOKEN) -> dict[str, str]:
    """Build a mock bearer token Authorization header."""

    return {"Authorization": f"Bearer {token}"}


def percent_encode(value: str) -> str:
    """OAuth 1.0a percent-encoding helper."""

    return quote(value, safe="~")


def build_oauth_v1_header(
    *,
    url: str,
    method: str = "POST",
    consumer_key: str = DEFAULT_OAUTH1_CONSUMER_KEY,
    consumer_secret: str = DEFAULT_OAUTH1_CONSUMER_SECRET,
    timestamp: str = "1760000000",
    nonce: str = "nonce-1",
    signature_method: str = "HMAC-SHA1",
) -> str:
    """Build a valid mock OAuth 1.0a Authorization header."""

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
            (percent_encode(key), percent_encode(value)) for key, value in params.items()
        )
    )
    base_string = "&".join(
        [
            percent_encode(method),
            percent_encode(url),
            percent_encode(normalized),
        ]
    )
    signing_key = f"{percent_encode(consumer_secret)}&"
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
    values = ", ".join(f'{key}="{percent_encode(value)}"' for key, value in header_params.items())
    return f"OAuth {values}"
