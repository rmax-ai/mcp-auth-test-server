"""RFC 9728 protected resource metadata."""

from __future__ import annotations

from fastapi import APIRouter, Request

from mcp_auth_test_server.discovery import (
    AUTHORIZATION_SERVER_METADATA_PATH,
    BEARER_TOKEN_RESOURCE_PATH,
    MOCK_SCOPES,
    OAUTH_V21_RESOURCE_PATH,
    PROTECTED_RESOURCE_METADATA_PATH,
    build_absolute_url,
    build_discovery_url,
)

router = APIRouter()


def build_protected_resource_metadata(
    request: Request,
    *,
    resource: str | None = None,
) -> dict[str, object]:
    """Return mock protected resource metadata for a supported MCP endpoint."""

    resolved_resource = resource or build_absolute_url(request, BEARER_TOKEN_RESOURCE_PATH)
    oauth_v21_resource = build_absolute_url(request, OAUTH_V21_RESOURCE_PATH)

    return {
        "resource": resolved_resource,
        "authorization_servers": [
            build_discovery_url(
                request,
                AUTHORIZATION_SERVER_METADATA_PATH,
                resource=resolved_resource if resolved_resource == oauth_v21_resource else None,
            ),
        ],
        "bearer_methods_supported": ["header"],
        "scopes_supported": MOCK_SCOPES,
    }


@router.get(PROTECTED_RESOURCE_METADATA_PATH)
async def oauth_protected_resource_metadata(request: Request) -> dict[str, object]:
    """Expose mock protected resource metadata for RFC 9728 discovery."""

    resource = request.query_params.get("resource")
    return build_protected_resource_metadata(request, resource=resource)
