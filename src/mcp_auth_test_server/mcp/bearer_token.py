"""Bearer-token-protected MCP endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from mcp_auth_test_server.auth.bearer import (
    BearerAuthError,
    mint_bearer_token,
    validate_bearer_token_header,
)
from mcp_auth_test_server.discovery import PROTECTED_RESOURCE_METADATA_PATH, build_absolute_url
from mcp_auth_test_server.mcp.base import BaseMCPHandler, JsonRpcError, RequestAuditContext
from mcp_auth_test_server.mcp.tools import get_core_tools
from mcp_auth_test_server.openapi_examples import (
    MCP_REQUEST_BODY,
    MCP_RESPONSES,
    UNAUTHORIZED_RESPONSE,
)

router = APIRouter(tags=["MCP: Bearer Token"])

handler = BaseMCPHandler(
    server_name="mcp-auth-test-server",
    server_version="0.1.0",
    instructions="This endpoint requires a static mock bearer token.",
    tools=get_core_tools(),
)


@router.post("/mcp/bearer-token/mint")
async def mint_endpoint() -> JSONResponse:
    """Mint a short-lived bearer token for the /mcp/bearer-token endpoint."""

    return JSONResponse(status_code=200, content=mint_bearer_token())


@router.post(
    "/mcp/bearer-token",
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
        resource_metadata_url = build_absolute_url(request, PROTECTED_RESOURCE_METADATA_PATH)
        return JSONResponse(
            status_code=401,
            content={"detail": exc.description},
            headers={
                "WWW-Authenticate": exc.to_www_authenticate(
                    resource_metadata=resource_metadata_url,
                ),
            },
        )

    source_ip = request.client.host if request.client is not None else "-"
    audit_context = RequestAuditContext(
        endpoint="/mcp/bearer-token",
        auth_scheme="bearer",
        caller="static-bearer-token",
        source_ip=source_ip,
    )

    try:
        payload = await request.json()
    except ValueError as exc:
        error = JsonRpcError(-32700, "Parse error", data=str(exc))
        return JSONResponse(status_code=400, content=error.as_response(None))

    try:
        status_code, response_payload = await handler.handle_message(
            payload,
            audit_context=audit_context,
        )
    except JsonRpcError as exc:
        return JSONResponse(status_code=400, content=exc.as_response(payload.get("id")))

    if response_payload is None:
        return Response(status_code=204)
    return JSONResponse(status_code=status_code, content=response_payload)
