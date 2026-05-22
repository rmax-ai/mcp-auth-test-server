"""RFC 9728 protected resource metadata."""

from __future__ import annotations

from fastapi import APIRouter, Request

from mcp_auth_test_server.discovery import (
    AUTHORIZATION_SERVER_METADATA_PATH,
    MOCK_SCOPES,
    OAUTH_V21_RESOURCE_PATH,
    PROTECTED_RESOURCE_METADATA_PATH,
    build_absolute_url,
    build_discovery_url,
)
from mcp_auth_test_server.openapi_examples import (
    PROTECTED_RESOURCE_METADATA_PARAMETERS,
    PROTECTED_RESOURCE_METADATA_RESPONSES,
)

router = APIRouter(tags=["Discovery"])


def build_protected_resource_metadata(
    request: Request,
    *,
    resource: str | None = None,
) -> dict[str, object]:
    """Return mock protected resource metadata for a supported MCP endpoint.

    Defaults to the OAuth 2.1 protected resource, which aligns with RFC 9728
    discovery as used by the MCP specification.
    """

    oauth_v21_resource = build_absolute_url(request, OAUTH_V21_RESOURCE_PATH)
    resolved_resource = resource or oauth_v21_resource

    return {
        "resource": resolved_resource,
        "authorization_servers": [
            build_discovery_url(
                request,
                AUTHORIZATION_SERVER_METADATA_PATH,
                resource=resolved_resource,
            ),
        ],
        "bearer_methods_supported": ["header"],
        "scopes_supported": MOCK_SCOPES,
    }


@router.get(
    PROTECTED_RESOURCE_METADATA_PATH,
    responses=PROTECTED_RESOURCE_METADATA_RESPONSES,
    openapi_extra={"parameters": PROTECTED_RESOURCE_METADATA_PARAMETERS},
)
async def oauth_protected_resource_metadata(request: Request) -> dict[str, object]:
    """Expose mock protected resource metadata for RFC 9728 discovery."""

    resource = request.query_params.get("resource")
    return build_protected_resource_metadata(request, resource=resource)
