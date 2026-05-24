"""Shared helpers for OAuth discovery documents."""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import Request

PROTECTED_RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource"
AUTHORIZATION_SERVER_METADATA_PATH = "/.well-known/oauth-authorization-server"

BEARER_TOKEN_RESOURCE_PATH = "/mcp/bearer-token"
OAUTH_RESOURCE_PATH = "/mcp/oauth"
MOCK_AUTHORIZATION_ENDPOINT_PATH = "/oauth/authorize"
MOCK_TOKEN_ENDPOINT_PATH = "/oauth/token"
MOCK_REGISTRATION_ENDPOINT_PATH = "/oauth/register"
MOCK_DEVICE_AUTHORIZATION_ENDPOINT_PATH = "/oauth/device/authorize"
TEST_BEARER_TOKEN_MINT_PATH = "/test-auth/bearer-token/mint"

MOCK_SCOPES = ["mcp:read", "mcp:write"]


def get_origin_url(request: Request) -> str:
    """Return the request origin without a trailing slash."""

    return str(request.base_url).rstrip("/")


def build_absolute_url(request: Request, path: str) -> str:
    """Build an absolute URL for a server-local path."""

    return f"{get_origin_url(request)}{path}"


def build_discovery_url(
    request: Request,
    path: str,
    *,
    resource: str | None = None,
) -> str:
    """Build a discovery URL with an optional resource query parameter."""

    base_url = build_absolute_url(request, path)
    if resource is None:
        return base_url
    return f"{base_url}?{urlencode({'resource': resource})}"
