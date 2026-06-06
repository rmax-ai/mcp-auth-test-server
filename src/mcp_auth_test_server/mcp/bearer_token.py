"""Bearer-token-protected MCP endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from mcp_auth_test_server.auth.bearer import (
    BearerAuthError,
    mint_bearer_token,
    validate_bearer_token_header,
)
from mcp_auth_test_server.discovery import TEST_BEARER_TOKEN_MINT_PATH
from mcp_auth_test_server.mcp.base import (
    BaseMCPHandler,
    RequestAuditContext,
    handle_mcp_request,
)
from mcp_auth_test_server.mcp.tools import get_core_tools
from mcp_auth_test_server.openapi_examples import (
    MCP_REQUEST_BODY,
    MCP_RESPONSES,
    UNAUTHORIZED_RESPONSE,
)

router = APIRouter()

handler = BaseMCPHandler(
    server_name="mcp-auth-test-server",
    server_version="0.1.0",
    instructions="This endpoint requires a static mock bearer token.",
    tools=get_core_tools(),
)


@router.post(TEST_BEARER_TOKEN_MINT_PATH, tags=["Auth: Bearer Token"])
async def mint_endpoint() -> JSONResponse:
    """Mint a short-lived bearer token for the static bearer MCP endpoint."""

    return JSONResponse(status_code=200, content=mint_bearer_token())


@router.post(
    "/mcp/bearer-token",
    tags=["MCP Endpoints"],
    responses={
        **MCP_RESPONSES,
        401: UNAUTHORIZED_RESPONSE,
    },
    openapi_extra={
        **MCP_REQUEST_BODY,
        "security": [{"MintedBearerToken": []}],
    },
)
async def bearer_token_endpoint(request: Request) -> Response:
    """Require a static bearer token before handling MCP JSON-RPC."""

    try:
        validate_bearer_token_header(request.headers.get("authorization"))
    except BearerAuthError as exc:
        return JSONResponse(
            status_code=401,
            content={"detail": exc.description},
            headers={"WWW-Authenticate": exc.to_www_authenticate()},
        )

    source_ip = request.client.host if request.client is not None else "-"
    audit_context = RequestAuditContext(
        endpoint="/mcp/bearer-token",
        auth_scheme="bearer",
        caller="static-bearer-token",
        source_ip=source_ip,
    )

    return await handle_mcp_request(
        request,
        handler=handler,
        audit_context=audit_context,
    )
