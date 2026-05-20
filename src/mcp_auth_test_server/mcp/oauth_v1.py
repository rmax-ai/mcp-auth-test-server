"""OAuth 1.0a-protected MCP endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from mcp_auth_test_server.auth.oauth_v1 import OAuth1Error, validate_oauth_v1_request
from mcp_auth_test_server.mcp.base import BaseMCPHandler, JsonRpcError
from mcp_auth_test_server.mcp.tools import get_core_tools

router = APIRouter()

handler = BaseMCPHandler(
    server_name="mcp-auth-test-server",
    server_version="0.1.0",
    instructions=(
        "This endpoint requires an OAuth 1.0a Authorization header signed with HMAC-SHA1."
    ),
    tools=get_core_tools(),
)


@router.post("/mcp/oauth-v1")
async def oauth_v1_endpoint(request: Request) -> Response:
    """Require a valid OAuth 1.0a signature before handling MCP JSON-RPC."""

    try:
        validate_oauth_v1_request(
            method=request.method,
            url=str(request.url),
            authorization_header=request.headers.get("authorization"),
        )
    except OAuth1Error as exc:
        return JSONResponse(
            status_code=401,
            content={"detail": exc.description},
            headers={"WWW-Authenticate": exc.to_www_authenticate()},
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
