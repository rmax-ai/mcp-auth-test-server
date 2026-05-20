"""RFC 9728 protected resource metadata."""

from __future__ import annotations

from fastapi import APIRouter, Request

from mcp_auth_test_server.discovery import (
    AUTHORIZATION_SERVER_METADATA_PATH,
    BEARER_TOKEN_RESOURCE_PATH,
    MOCK_SCOPES,
    PROTECTED_RESOURCE_METADATA_PATH,
    build_absolute_url,
)

router = APIRouter()


def build_protected_resource_metadata(request: Request) -> dict[str, object]:
    """Return mock protected resource metadata for the bearer-token MCP endpoint."""

    return {
        "resource": build_absolute_url(request, BEARER_TOKEN_RESOURCE_PATH),
        "authorization_servers": [
            build_absolute_url(request, AUTHORIZATION_SERVER_METADATA_PATH),
        ],
        "bearer_methods_supported": ["header"],
        "scopes_supported": MOCK_SCOPES,
    }


@router.get(PROTECTED_RESOURCE_METADATA_PATH)
async def oauth_protected_resource_metadata(request: Request) -> dict[str, object]:
    """Expose mock protected resource metadata for RFC 9728 discovery."""

    return build_protected_resource_metadata(request)
