"""OAuth 2.0 client-credentials protected endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from mcp_auth_test_server.auth.bearer import BearerAuthError
from mcp_auth_test_server.auth.oauth import (
    CLIENT_CREDENTIALS_GRANT_TYPE,
    validate_access_token_grant_type,
    validate_access_token_header,
)
from mcp_auth_test_server.mcp.base import BaseMCPHandler, JsonRpcError, RequestAuditContext
from mcp_auth_test_server.mcp.tools import get_core_tools
from mcp_auth_test_server.openapi_examples import (
    MCP_REQUEST_BODY,
    MCP_RESPONSES,
    UNAUTHORIZED_RESPONSE,
)

router = APIRouter(tags=["OAuth 2.0: Client Credentials"])

handler = BaseMCPHandler(
    server_name="mcp-auth-test-server",
    server_version="0.1.0",
    instructions=(
        "This endpoint requires an OAuth 2.0 bearer token obtained via client credentials."
    ),
    tools=get_core_tools(),
)


@router.post(
    "/mcp/oauth-v2-client-creds",
    responses={
        **MCP_RESPONSES,
        401: UNAUTHORIZED_RESPONSE,
    },
    openapi_extra=MCP_REQUEST_BODY,
)
async def oauth_v2_client_credentials_endpoint(request: Request) -> Response:
    """Require a client-credentials OAuth access token before handling MCP JSON-RPC."""

    try:
        token_record = validate_access_token_header(request.headers.get("authorization"))
        validate_access_token_grant_type(
            token_record,
            expected_grant_type=CLIENT_CREDENTIALS_GRANT_TYPE,
        )
    except BearerAuthError as exc:
        return JSONResponse(
            status_code=401,
            content={"detail": exc.description},
            headers={"WWW-Authenticate": exc.to_www_authenticate()},
        )

    source_ip = request.client.host if request.client is not None else "-"
    audit_context = RequestAuditContext(
        endpoint="/mcp/oauth-v2-client-creds",
        auth_scheme="oauth2",
        caller=token_record.client_id,
        source_ip=source_ip,
        client_id=token_record.client_id,
        scope=token_record.scope,
        grant_type=token_record.grant_type,
        audience=token_record.audience or "-",
        issuer=token_record.issuer or "-",
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
    return JSONResponse(status_code=status_code or 200, content=response_payload)
