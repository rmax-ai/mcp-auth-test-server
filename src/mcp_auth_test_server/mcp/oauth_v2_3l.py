"""OAuth 2.0 authorization-code + PKCE protected endpoints."""

from __future__ import annotations

from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from mcp_auth_test_server.auth.bearer import BearerAuthError
from mcp_auth_test_server.auth.oauth import (
    AUTHORIZATION_CODE_GRANT_TYPE,
    CLIENT_CREDENTIALS_GRANT_TYPE,
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
from mcp_auth_test_server.mcp.base import BaseMCPHandler, JsonRpcError
from mcp_auth_test_server.mcp.tools import get_core_tools

router = APIRouter()

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


@router.get("/oauth/authorize")
async def authorize(request: Request) -> Response:
    """Render mock consent for a valid PKCE authorization request."""

    try:
        auth_request = validate_authorization_request(dict(request.query_params))
    except OAuthError as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.as_response())

    if request.query_params.get("auto_approve") == "true":
        record = oauth_token_store.issue_authorization_code(
            client_id=auth_request.client_id,
            redirect_uri=auth_request.redirect_uri,
            scope=auth_request.scope,
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


@router.post("/oauth/authorize/consent")
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


@router.post("/oauth/token")
async def token(request: Request) -> JSONResponse:
    """Issue bearer access tokens for supported OAuth grant types."""

    form_data = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
    grant_type = _form_field(form_data, "grant_type")
    client_id = _form_field(form_data, "client_id")

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
        return JSONResponse(
            status_code=200,
            content={
                "access_token": access_token.access_token,
                "token_type": access_token.token_type,
                "expires_in": ACCESS_TOKEN_TTL_SECONDS,
                "scope": access_token.scope,
            },
        )

    if grant_type == CLIENT_CREDENTIALS_GRANT_TYPE:
        client_secret = _form_field(form_data, "client_secret")
        requested_scope = _form_field(form_data, "scope") or "mcp:read"

        if not client_id or not client_secret:
            error = OAuthError(
                error="invalid_request",
                description="client_id and client_secret are required",
                status_code=400,
            )
            return JSONResponse(status_code=error.status_code, content=error.as_response())

        if not oauth_token_store.is_valid_client_credentials(
            client_id=client_id,
            client_secret=client_secret,
        ):
            error = OAuthError(
                error="invalid_client",
                description="client credentials are invalid",
                status_code=401,
            )
            return JSONResponse(status_code=error.status_code, content=error.as_response())

        try:
            validate_scope(requested_scope)
        except OAuthError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.as_response())

        access_token = oauth_token_store.issue_access_token(
            client_id=client_id,
            scope=requested_scope,
            grant_type=CLIENT_CREDENTIALS_GRANT_TYPE,
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
        description="grant_type must be authorization_code or client_credentials",
        status_code=400,
    )
    return JSONResponse(status_code=error.status_code, content=error.as_response())


@router.post("/mcp/oauth-v2-auth-code")
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
