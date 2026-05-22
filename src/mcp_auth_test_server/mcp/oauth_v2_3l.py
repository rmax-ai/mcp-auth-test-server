"""OAuth 2.0 authorization-code + PKCE protected endpoints."""

from __future__ import annotations

import logging
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from mcp_auth_test_server.auth.bearer import BearerAuthError
from mcp_auth_test_server.auth.dynamic_registration import (
    validate_registered_authorization_client,
    validate_registered_token_client,
)
from mcp_auth_test_server.auth.oauth import (
    AUTHORIZATION_CODE_GRANT_TYPE,
    CLIENT_CREDENTIALS_GRANT_TYPE,
    REFRESH_TOKEN_GRANT_TYPE,
    OAuthError,
    build_redirect_uri,
    validate_access_token_grant_type,
    validate_access_token_header,
    validate_authorization_request,
    validate_scope,
    verify_pkce_code_verifier,
)
from mcp_auth_test_server.auth.token_store import (
    ACCESS_TOKEN_TTL_SECONDS,
    oauth_token_store,
)
from mcp_auth_test_server.discovery import MOCK_AUTHORIZATION_ENDPOINT_PATH
from mcp_auth_test_server.mcp.base import BaseMCPHandler, JsonRpcError, RequestAuditContext
from mcp_auth_test_server.mcp.tools import get_core_tools
from mcp_auth_test_server.openapi_examples import (
    AUTHORIZE_CONSENT_REQUEST_BODY,
    AUTHORIZE_PARAMETERS,
    AUTHORIZE_RESPONSES,
    MCP_REQUEST_BODY,
    MCP_RESPONSES,
    OAUTH_ERROR_RESPONSE,
    TOKEN_REQUEST_BODY,
    TOKEN_RESPONSE,
    UNAUTHORIZED_RESPONSE,
)

router = APIRouter(tags=["OAuth 2.0: Auth Code + PKCE"])
logger = logging.getLogger("mcp_auth_test_server.audit")

handler = BaseMCPHandler(
    server_name="mcp-auth-test-server",
    server_version="0.1.0",
    instructions=(
        "This endpoint requires an OAuth 2.0 bearer token obtained via authorization code + PKCE."
    ),
    tools=get_core_tools(),
)


def _form_field(form_data: dict[str, list[str]], name: str) -> str | None:
    values = form_data.get(name)
    if not values:
        return None
    return values[0]


def _token_response(
    *,
    access_token: str,
    scope: str,
    refresh_token: str | None = None,
) -> dict[str, object]:
    response: dict[str, object] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        "scope": scope,
    }
    if refresh_token is not None:
        response["refresh_token"] = refresh_token
    return response


def _render_consent_page(
    *,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str | None,
    code_challenge: str,
    code_challenge_method: str,
) -> str:
    state_markup = (
        f'<input type="hidden" name="state" value="{state}" />' if state is not None else ""
    )
    return f"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Authorize MCP Test Client</title>
  </head>
  <body>
    <h1>Mock OAuth Consent</h1>
    <p>
      Client <strong>{client_id}</strong> is requesting access to scope
      <strong>{scope}</strong>.
    </p>
    <form method="post" action="/oauth/authorize/consent">
      <input type="hidden" name="client_id" value="{client_id}" />
      <input type="hidden" name="redirect_uri" value="{redirect_uri}" />
      <input type="hidden" name="scope" value="{scope}" />
      <input type="hidden" name="code_challenge" value="{code_challenge}" />
      <input type="hidden" name="code_challenge_method" value="{code_challenge_method}" />
      {state_markup}
      <button type="submit" name="decision" value="approve">Approve</button>
      <button type="submit" name="decision" value="deny">Deny</button>
    </form>
  </body>
</html>
""".strip()


@router.get(
    "/oauth/authorize",
    responses=AUTHORIZE_RESPONSES,
    openapi_extra={"parameters": AUTHORIZE_PARAMETERS},
)
async def authorize(request: Request) -> Response:
    """Render mock consent for a valid PKCE authorization request."""

    try:
        auth_request = validate_authorization_request(dict(request.query_params))
    except OAuthError as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.as_response())
    try:
        validate_registered_authorization_client(
            client_id=auth_request.client_id,
            redirect_uri=auth_request.redirect_uri,
        )
    except OAuthError as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.as_response())

    if request.query_params.get("auto_approve") == "true":
        record = oauth_token_store.issue_authorization_code(
            client_id=auth_request.client_id,
            redirect_uri=auth_request.redirect_uri,
            scope=auth_request.scope,
            resource=MOCK_AUTHORIZATION_ENDPOINT_PATH,
            code_challenge=auth_request.code_challenge,
            code_challenge_method=auth_request.code_challenge_method,
        )
        return RedirectResponse(
            url=build_redirect_uri(
                auth_request.redirect_uri,
                code=record.code,
                state=auth_request.state,
            ),
            status_code=302,
        )

    return HTMLResponse(
        _render_consent_page(
            client_id=auth_request.client_id,
            redirect_uri=auth_request.redirect_uri,
            scope=auth_request.scope,
            state=auth_request.state,
            code_challenge=auth_request.code_challenge,
            code_challenge_method=auth_request.code_challenge_method,
        ),
    )


@router.post(
    "/oauth/authorize/consent",
    responses={
        302: {"description": "Redirect back to the client with either `code` or `error`."},
        400: OAUTH_ERROR_RESPONSE,
    },
    openapi_extra=AUTHORIZE_CONSENT_REQUEST_BODY,
)
async def authorize_consent(request: Request) -> Response:
    """Simulate browser consent and redirect with code or error."""

    form_data = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)

    try:
        auth_request = validate_authorization_request(
            {
                "response_type": "code",
                "client_id": _form_field(form_data, "client_id"),
                "redirect_uri": _form_field(form_data, "redirect_uri"),
                "scope": _form_field(form_data, "scope"),
                "state": _form_field(form_data, "state"),
                "code_challenge": _form_field(form_data, "code_challenge"),
                "code_challenge_method": _form_field(form_data, "code_challenge_method"),
            }
        )
    except OAuthError as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.as_response())
    try:
        validate_registered_authorization_client(
            client_id=auth_request.client_id,
            redirect_uri=auth_request.redirect_uri,
        )
    except OAuthError as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.as_response())

    decision = _form_field(form_data, "decision")
    if decision != "approve":
        return RedirectResponse(
            url=build_redirect_uri(
                auth_request.redirect_uri,
                state=auth_request.state,
                error="access_denied",
            ),
            status_code=302,
        )

    record = oauth_token_store.issue_authorization_code(
        client_id=auth_request.client_id,
        redirect_uri=auth_request.redirect_uri,
        scope=auth_request.scope,
        resource=MOCK_AUTHORIZATION_ENDPOINT_PATH,
        code_challenge=auth_request.code_challenge,
        code_challenge_method=auth_request.code_challenge_method,
    )
    return RedirectResponse(
        url=build_redirect_uri(
            auth_request.redirect_uri,
            code=record.code,
            state=auth_request.state,
        ),
        status_code=302,
    )


@router.post(
    "/oauth/token",
    responses={
        200: TOKEN_RESPONSE,
        400: OAUTH_ERROR_RESPONSE,
        401: OAUTH_ERROR_RESPONSE,
    },
    openapi_extra=TOKEN_REQUEST_BODY,
)
async def token(request: Request) -> JSONResponse:
    """Issue bearer access tokens for supported OAuth grant types."""

    form_data = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
    grant_type = _form_field(form_data, "grant_type")
    client_id = _form_field(form_data, "client_id")
    client_secret = _form_field(form_data, "client_secret")

    if grant_type == AUTHORIZATION_CODE_GRANT_TYPE:
        code = _form_field(form_data, "code")
        redirect_uri = _form_field(form_data, "redirect_uri")
        code_verifier = _form_field(form_data, "code_verifier")

        if not code or not redirect_uri or not client_id or not code_verifier:
            error = OAuthError(
                error="invalid_request",
                description="code, redirect_uri, client_id, and code_verifier are required",
                status_code=400,
            )
            return JSONResponse(status_code=error.status_code, content=error.as_response())
        try:
            client = validate_registered_token_client(
                client_id=client_id,
                grant_type=AUTHORIZATION_CODE_GRANT_TYPE,
                client_secret=client_secret,
            )
        except OAuthError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.as_response())

        code_record = oauth_token_store.consume_authorization_code(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
        )
        if code_record is None:
            error = OAuthError(
                error="invalid_grant",
                description="authorization code is invalid",
                status_code=400,
            )
            return JSONResponse(status_code=error.status_code, content=error.as_response())

        if not verify_pkce_code_verifier(
            code_verifier=code_verifier,
            code_challenge=code_record.code_challenge,
        ):
            error = OAuthError(
                error="invalid_grant",
                description="code_verifier does not match code_challenge",
                status_code=400,
            )
            return JSONResponse(status_code=error.status_code, content=error.as_response())

        access_token = oauth_token_store.issue_access_token(
            client_id=client_id,
            scope=code_record.scope,
            grant_type=AUTHORIZATION_CODE_GRANT_TYPE,
        )
        refresh_token = None
        if REFRESH_TOKEN_GRANT_TYPE in client.grant_types:
            refresh_token = oauth_token_store.issue_refresh_token(
                client_id=client_id,
                scope=code_record.scope,
                grant_type=AUTHORIZATION_CODE_GRANT_TYPE,
            )
        logger.info(
            "oauth token issued endpoint=%s client_id=%s grant_type=%s scope=%s "
            "audience=%s issuer=%s refresh_token_issued=%s",
            "/oauth/token",
            client_id,
            AUTHORIZATION_CODE_GRANT_TYPE,
            access_token.scope,
            access_token.audience or "-",
            access_token.issuer or "-",
            refresh_token is not None,
        )
        return JSONResponse(
            status_code=200,
            content=_token_response(
                access_token=access_token.access_token,
                scope=access_token.scope,
                refresh_token=(refresh_token.refresh_token if refresh_token is not None else None),
            ),
        )

    if grant_type == REFRESH_TOKEN_GRANT_TYPE:
        refresh_token = _form_field(form_data, "refresh_token")

        if not refresh_token or not client_id:
            error = OAuthError(
                error="invalid_request",
                description="refresh_token and client_id are required",
                status_code=400,
            )
            return JSONResponse(status_code=error.status_code, content=error.as_response())
        try:
            validate_registered_token_client(
                client_id=client_id,
                grant_type=REFRESH_TOKEN_GRANT_TYPE,
                client_secret=client_secret,
            )
        except OAuthError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.as_response())

        refresh_record = oauth_token_store.get_refresh_token(refresh_token)
        if refresh_record is None or refresh_record.client_id != client_id:
            error = OAuthError(
                error="invalid_grant",
                description="refresh_token is invalid",
                status_code=400,
            )
            return JSONResponse(status_code=error.status_code, content=error.as_response())

        access_token = oauth_token_store.issue_access_token(
            client_id=client_id,
            scope=refresh_record.scope,
            grant_type=refresh_record.grant_type,
            audience=refresh_record.audience,
            issuer=refresh_record.issuer,
        )
        logger.info(
            "oauth token issued endpoint=%s client_id=%s grant_type=%s scope=%s "
            "audience=%s issuer=%s refresh_token_issued=%s",
            "/oauth/token",
            client_id,
            REFRESH_TOKEN_GRANT_TYPE,
            access_token.scope,
            access_token.audience or "-",
            access_token.issuer or "-",
            True,
        )
        return JSONResponse(
            status_code=200,
            content=_token_response(
                access_token=access_token.access_token,
                scope=access_token.scope,
                refresh_token=refresh_record.refresh_token,
            ),
        )

    if grant_type == CLIENT_CREDENTIALS_GRANT_TYPE:
        requested_scope = _form_field(form_data, "scope") or "mcp:read"

        if not client_id or not client_secret:
            error = OAuthError(
                error="invalid_request",
                description="client_id and client_secret are required",
                status_code=400,
            )
            return JSONResponse(status_code=error.status_code, content=error.as_response())

        try:
            validate_registered_token_client(
                client_id=client_id,
                grant_type=CLIENT_CREDENTIALS_GRANT_TYPE,
                client_secret=client_secret,
            )
        except OAuthError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.as_response())

        try:
            validate_scope(requested_scope)
        except OAuthError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.as_response())

        access_token = oauth_token_store.issue_access_token(
            client_id=client_id,
            scope=requested_scope,
            grant_type=CLIENT_CREDENTIALS_GRANT_TYPE,
        )
        logger.info(
            "oauth token issued endpoint=%s client_id=%s grant_type=%s scope=%s "
            "audience=%s issuer=%s refresh_token_issued=%s",
            "/oauth/token",
            client_id,
            CLIENT_CREDENTIALS_GRANT_TYPE,
            access_token.scope,
            access_token.audience or "-",
            access_token.issuer or "-",
            False,
        )
        return JSONResponse(
            status_code=200,
            content={
                "access_token": access_token.access_token,
                "token_type": access_token.token_type,
                "expires_in": ACCESS_TOKEN_TTL_SECONDS,
                "scope": access_token.scope,
            },
        )

    error = OAuthError(
        error="unsupported_grant_type",
        description="grant_type must be authorization_code, refresh_token, or client_credentials",
        status_code=400,
    )
    return JSONResponse(status_code=error.status_code, content=error.as_response())


@router.post(
    "/mcp/oauth-v2-auth-code",
    responses={
        **MCP_RESPONSES,
        401: UNAUTHORIZED_RESPONSE,
    },
    openapi_extra=MCP_REQUEST_BODY,
)
async def oauth_v2_auth_code_endpoint(request: Request) -> Response:
    """Require an issued OAuth access token before handling MCP JSON-RPC."""

    try:
        token_record = validate_access_token_header(request.headers.get("authorization"))
        validate_access_token_grant_type(
            token_record,
            expected_grant_type=AUTHORIZATION_CODE_GRANT_TYPE,
        )
    except BearerAuthError as exc:
        return JSONResponse(
            status_code=401,
            content={"detail": exc.description},
            headers={"WWW-Authenticate": exc.to_www_authenticate()},
        )

    source_ip = request.client.host if request.client is not None else "-"
    audit_context = RequestAuditContext(
        endpoint="/mcp/oauth-v2-auth-code",
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
    return JSONResponse(status_code=status_code, content=response_payload)
