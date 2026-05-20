"""RFC 8414 authorization server metadata."""

from __future__ import annotations

from fastapi import APIRouter, Request

from mcp_auth_test_server.discovery import (
    AUTHORIZATION_SERVER_METADATA_PATH,
    MOCK_AUTHORIZATION_ENDPOINT_PATH,
    MOCK_REGISTRATION_ENDPOINT_PATH,
    MOCK_SCOPES,
    MOCK_TOKEN_ENDPOINT_PATH,
    build_absolute_url,
    get_origin_url,
)

router = APIRouter()


def build_auth_server_metadata(request: Request) -> dict[str, object]:
    """Return authorization server metadata for the mock OAuth test flow."""

    return {
        "issuer": get_origin_url(request),
        "authorization_endpoint": build_absolute_url(
            request,
            MOCK_AUTHORIZATION_ENDPOINT_PATH,
        ),
        "token_endpoint": build_absolute_url(request, MOCK_TOKEN_ENDPOINT_PATH),
        "registration_endpoint": build_absolute_url(
            request,
            MOCK_REGISTRATION_ENDPOINT_PATH,
        ),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": MOCK_SCOPES,
    }


@router.get(AUTHORIZATION_SERVER_METADATA_PATH)
async def oauth_authorization_server_metadata(
    request: Request,
) -> dict[str, object]:
    """Expose authorization server metadata for RFC 8414 discovery."""

    return build_auth_server_metadata(request)
