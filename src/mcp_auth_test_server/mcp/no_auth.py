"""No-auth MCP endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from mcp_auth_test_server.mcp.base import BaseMCPHandler, JsonRpcError, RequestAuditContext
from mcp_auth_test_server.mcp.tools import get_core_tools
from mcp_auth_test_server.openapi_examples import MCP_REQUEST_BODY, MCP_RESPONSES

router = APIRouter(tags=["MCP: No Auth"])

handler = BaseMCPHandler(
    server_name="mcp-auth-test-server",
    server_version="0.1.0",
    instructions="This endpoint accepts MCP requests without authentication.",
    tools=get_core_tools(),
)


@router.post(
    "/mcp/no-auth",
    responses=MCP_RESPONSES,
    openapi_extra=MCP_REQUEST_BODY,
)
async def no_auth_endpoint(request: Request) -> Response:
    """Accept all MCP requests without authentication."""

    source_ip = request.client.host if request.client is not None else "-"
    audit_context = RequestAuditContext(
        endpoint="/mcp/no-auth",
        auth_scheme="none",
        caller="anonymous",
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
