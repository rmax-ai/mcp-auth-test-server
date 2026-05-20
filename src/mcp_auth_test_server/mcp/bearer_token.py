"""Bearer-token-protected MCP endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from mcp_auth_test_server.auth.bearer import BearerAuthError, validate_bearer_token_header
from mcp_auth_test_server.discovery import PROTECTED_RESOURCE_METADATA_PATH, build_absolute_url
from mcp_auth_test_server.mcp.base import BaseMCPHandler, JsonRpcError
from mcp_auth_test_server.mcp.tools import get_core_tools

router = APIRouter()

handler = BaseMCPHandler(
    server_name="mcp-auth-test-server",
    server_version="0.1.0",
    instructions="This endpoint requires a static mock bearer token.",
    tools=get_core_tools(),
)


@router.post("/mcp/bearer-token")
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

    try:
        payload = await request.json()
    except ValueError as exc:
        error = JsonRpcError(-32700, "Parse error", data=str(exc))
        return JSONResponse(status_code=400, content=error.as_response(None))

    try:
        status_code, response_payload = await handler.handle_message(payload)
    except JsonRpcError as exc:
        return JSONResponse(status_code=400, content=exc.as_response(payload.get("id")))

    if response_payload is None:
        return Response(status_code=204)
    return JSONResponse(status_code=status_code, content=response_payload)
