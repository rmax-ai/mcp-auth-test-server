"""Shared protocol helpers for end-to-end auth flow tests and live checks."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

from mcp_auth_test_server.auth.bearer import DEFAULT_BEARER_TOKEN


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
