"""OAuth 2.0 Device Authorization Grant (RFC 8628) protected endpoints."""

from __future__ import annotations

import logging
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from mcp_auth_test_server.auth.bearer import BearerAuthError
from mcp_auth_test_server.auth.oauth import (
    DEVICE_CODE_GRANT_TYPE,
    OAuthError,
    validate_access_token_grant_type,
    validate_access_token_header,
    validate_scope,
)
from mcp_auth_test_server.auth.token_store import (
    DEVICE_CODE_INTERVAL_SECONDS,
    DEVICE_CODE_TTL_SECONDS,
    oauth_token_store,
)
from mcp_auth_test_server.mcp.base import BaseMCPHandler, JsonRpcError, RequestAuditContext
from mcp_auth_test_server.mcp.tools import get_core_tools
from mcp_auth_test_server.openapi_examples import (
    MCP_REQUEST_BODY,
    MCP_RESPONSES,
    OAUTH_ERROR_RESPONSE,
    TOKEN_RESPONSE,
    UNAUTHORIZED_RESPONSE,
)

router = APIRouter(tags=["OAuth 2.0: Device Flow"])
logger = logging.getLogger("mcp_auth_test_server.audit")

handler = BaseMCPHandler(
    server_name="mcp-auth-test-server",
    server_version="0.1.0",
    instructions=(
        "This endpoint requires an OAuth access token obtained via device authorization grant."
    ),
    tools=get_core_tools(),
)


def _form_field(form_data: dict[str, list[str]], name: str) -> str | None:
    values = form_data.get(name)
    if not values:
        return None
    return values[0]


def _render_verify_page(
    *,
    user_code: str | None = None,
) -> str:
    prefilled = f'value="{user_code}"' if user_code else ""
    return f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Verify Device Code</title>
  </head>
  <body>
    <h1>Mock Device Verification</h1>
    <p>Enter the user code displayed on your device to approve access.</p>
    <form method="post" action="/oauth/device/verify/consent">
      <label for="user_code">User Code:</label>
      <input type="text" name="user_code" id="user_code" {prefilled} />
      <button type="submit" name="decision" value="approve">Approve</button>
      <button type="submit" name="decision" value="deny">Deny</button>
    </form>
  </body>
</html>
""".strip()


def _render_success_page() -> str:
    return """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Device Verified</title>
  </head>
  <body>
    <h1>Device Verified</h1>
    <p>Your device has been successfully authorized.</p>
  </body>
</html>
""".strip()


def _render_denied_page() -> str:
    return """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Device Denied</title>
  </head>
  <body>
    <h1>Device Denied</h1>
    <p>Authorization was denied. Please try again on your device.</p>
  </body>
</html>
""".strip()


@router.post(
    "/oauth/device/authorize",
    responses={
        200: TOKEN_RESPONSE,
        400: OAUTH_ERROR_RESPONSE,
    },
)
async def device_authorize(request: Request) -> JSONResponse:
    """Issue a device code and user code for the device authorization grant."""

    form_data = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
    client_id = _form_field(form_data, "client_id")
    scope = _form_field(form_data, "scope") or "mcp:read"

    if not client_id:
        error = OAuthError(
            error="invalid_request",
            description="client_id is required",
            status_code=400,
        )
        return JSONResponse(status_code=error.status_code, content=error.as_response())

    client = oauth_token_store.get_client(client_id)
    if client is None:
        error = OAuthError(
            error="invalid_client",
            description="client is not registered",
            status_code=400,
        )
        return JSONResponse(status_code=error.status_code, content=error.as_response())

    if DEVICE_CODE_GRANT_TYPE not in client.grant_types:
        error = OAuthError(
            error="unauthorized_client",
            description="client is not authorized for device_code grant",
            status_code=400,
        )
        return JSONResponse(status_code=error.status_code, content=error.as_response())

    try:
        validate_scope(scope)
    except OAuthError as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.as_response())

    record = oauth_token_store.issue_device_code(
        client_id=client_id,
        scope=scope,
    )

    verification_uri = f"{str(request.base_url).rstrip('/')}/oauth/device/verify"
    verification_uri_complete = f"{verification_uri}?user_code={record.user_code}"

    logger.info(
        "device code issued endpoint=%s client_id=%s scope=%s user_code=%s",
        "/oauth/device/authorize",
        client_id,
        scope,
        record.user_code,
    )

    return JSONResponse(
        status_code=200,
        content={
            "device_code": record.device_code,
            "user_code": record.user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_uri_complete,
            "expires_in": DEVICE_CODE_TTL_SECONDS,
            "interval": DEVICE_CODE_INTERVAL_SECONDS,
        },
    )


@router.get("/oauth/device/verify")
async def device_verify(user_code: str | None = None) -> HTMLResponse:
    """Render the device verification page with an optional pre-filled user code."""

    return HTMLResponse(_render_verify_page(user_code=user_code))


@router.post("/oauth/device/verify/consent")
async def device_verify_consent(request: Request) -> HTMLResponse:
    """Process device verification consent (approve or deny)."""

    form_data = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
    user_code = _form_field(form_data, "user_code")
    decision = _form_field(form_data, "decision")

    if decision == "approve" and user_code:
        record = oauth_token_store.verify_device_code(user_code)
        if record is not None:
            logger.info(
                "device code verified endpoint=%s client_id=%s user_code=%s",
                "/oauth/device/verify/consent",
                record.client_id,
                user_code,
            )
            return HTMLResponse(_render_success_page())

    logger.info(
        "device code denied endpoint=%s user_code=%s",
        "/oauth/device/verify/consent",
        user_code or "-",
    )
    return HTMLResponse(_render_denied_page())


@router.post(
    "/mcp/device-flow",
    responses={
        **MCP_RESPONSES,
        401: UNAUTHORIZED_RESPONSE,
    },
    openapi_extra=MCP_REQUEST_BODY,
)
async def device_flow_endpoint(request: Request) -> Response:
    """Require an OAuth access token obtained via device authorization grant."""

    try:
        token_record = validate_access_token_header(request.headers.get("authorization"))
        validate_access_token_grant_type(
            token_record,
            expected_grant_type=DEVICE_CODE_GRANT_TYPE,
        )
    except BearerAuthError as exc:
        return JSONResponse(
            status_code=401,
            content={"detail": exc.description},
            headers={"WWW-Authenticate": exc.to_www_authenticate()},
        )

    source_ip = request.client.host if request.client is not None else "-"
    audit_context = RequestAuditContext(
        endpoint="/mcp/device-flow",
        auth_scheme="oauth2-device",
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
    return JSONResponse(status_code=status_code, content=response_payload)
