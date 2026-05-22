"""OAuth 2.1 authorization server and protected MCP endpoint."""

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
    REFRESH_TOKEN_GRANT_TYPE,
    OAuthError,
    build_redirect_uri,
    validate_access_token_audience,
    validate_access_token_grant_type,
    validate_access_token_header,
    validate_access_token_issuer,
    verify_pkce_code_verifier,
)
from mcp_auth_test_server.auth.oauth_v21 import (
    validate_oauth_v21_authorization_request,
    validate_oauth_v21_refresh_resource,
    validate_oauth_v21_token_resource,
)
from mcp_auth_test_server.auth.token_store import (
    ACCESS_TOKEN_TTL_SECONDS,
    oauth_token_store,
)
from mcp_auth_test_server.discovery import (
    OAUTH_V21_RESOURCE_PATH,
    PROTECTED_RESOURCE_METADATA_PATH,
    build_absolute_url,
    build_discovery_url,
    get_origin_url,
)
from mcp_auth_test_server.mcp.base import BaseMCPHandler, JsonRpcError, RequestAuditContext
from mcp_auth_test_server.mcp.tools import get_core_tools

router = APIRouter()
logger = logging.getLogger("mcp_auth_test_server.audit")

handler = BaseMCPHandler(
    server_name="mcp-auth-test-server",
    server_version="0.1.0",
    instructions=(
        "This endpoint requires an OAuth 2.1 bearer token issued for this resource "
        "via authorization code + PKCE with S256."
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
    audience: str,
    issuer: str,
    refresh_token: str | None = None,
) -> dict[str, object]:
    response: dict[str, object] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        "scope": scope,
        "aud": audience,
        "iss": issuer,
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
    resource: str,
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
    <title>Authorize MCP OAuth 2.1 Test Client</title>
  </head>
  <body>
    <h1>Mock OAuth 2.1 Consent</h1>
    <p>
      Client <strong>{client_id}</strong> is requesting access to scope
      <strong>{scope}</strong> for resource <strong>{resource}</strong>.
    </p>
    <form method="post" action="/oauth-v21/authorize/consent">
      <input type="hidden" name="client_id" value="{client_id}" />
      <input type="hidden" name="redirect_uri" value="{redirect_uri}" />
      <input type="hidden" name="scope" value="{scope}" />
      <input type="hidden" name="resource" value="{resource}" />
      <input type="hidden" name="code_challenge" value="{code_challenge}" />
      <input type="hidden" name="code_challenge_method" value="{code_challenge_method}" />
      {state_markup}
      <button type="submit" name="decision" value="approve">Approve</button>
      <button type="submit" name="decision" value="deny">Deny</button>
    </form>
  </body>
</html>
""".strip()


def _oauth_v21_resource(request: Request) -> str:
    return build_absolute_url(request, OAUTH_V21_RESOURCE_PATH)


def _oauth_v21_resource_metadata_url(request: Request) -> str:
    return build_discovery_url(
        request,
        PROTECTED_RESOURCE_METADATA_PATH,
        resource=_oauth_v21_resource(request),
    )


@router.get("/oauth-v21/authorize")
async def authorize(request: Request) -> Response:
    """Render mock consent for a valid OAuth 2.1 authorization request."""

    issuer = get_origin_url(request)
    expected_resource = _oauth_v21_resource(request)

    try:
        auth_request = validate_oauth_v21_authorization_request(
            dict(request.query_params),
            expected_resource=expected_resource,
        )
    except OAuthError as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.as_response())
    try:
        validate_registered_authorization_client(
            client_id=auth_request.client_id,
            redirect_uri=auth_request.redirect_uri,
            required_token_endpoint_auth_method="none",
        )
    except OAuthError as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.as_response())

    if request.query_params.get("auto_approve") == "true":
        record = oauth_token_store.issue_authorization_code(
            client_id=auth_request.client_id,
            redirect_uri=auth_request.redirect_uri,
            scope=auth_request.scope,
            resource=auth_request.resource,
            code_challenge=auth_request.code_challenge,
            code_challenge_method=auth_request.code_challenge_method,
        )
        return RedirectResponse(
            url=build_redirect_uri(
                auth_request.redirect_uri,
                code=record.code,
                state=auth_request.state,
                iss=issuer,
            ),
            status_code=302,
        )

    return HTMLResponse(
        _render_consent_page(
            client_id=auth_request.client_id,
            redirect_uri=auth_request.redirect_uri,
            scope=auth_request.scope,
            state=auth_request.state,
            resource=auth_request.resource,
            code_challenge=auth_request.code_challenge,
            code_challenge_method=auth_request.code_challenge_method,
        ),
    )


@router.post("/oauth-v21/authorize/consent")
async def authorize_consent(request: Request) -> Response:
    """Simulate browser consent and redirect with code or error for OAuth 2.1."""

    form_data = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
    issuer = get_origin_url(request)
    expected_resource = _oauth_v21_resource(request)

    try:
        auth_request = validate_oauth_v21_authorization_request(
            {
                "response_type": "code",
                "client_id": _form_field(form_data, "client_id"),
                "redirect_uri": _form_field(form_data, "redirect_uri"),
                "scope": _form_field(form_data, "scope"),
                "state": _form_field(form_data, "state"),
                "resource": _form_field(form_data, "resource"),
                "code_challenge": _form_field(form_data, "code_challenge"),
                "code_challenge_method": _form_field(form_data, "code_challenge_method"),
            },
            expected_resource=expected_resource,
        )
    except OAuthError as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.as_response())
    try:
        validate_registered_authorization_client(
            client_id=auth_request.client_id,
            redirect_uri=auth_request.redirect_uri,
            required_token_endpoint_auth_method="none",
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
                iss=issuer,
            ),
            status_code=302,
        )

    record = oauth_token_store.issue_authorization_code(
        client_id=auth_request.client_id,
        redirect_uri=auth_request.redirect_uri,
        scope=auth_request.scope,
        resource=auth_request.resource,
        code_challenge=auth_request.code_challenge,
        code_challenge_method=auth_request.code_challenge_method,
    )
    return RedirectResponse(
        url=build_redirect_uri(
            auth_request.redirect_uri,
            code=record.code,
            state=auth_request.state,
            iss=issuer,
        ),
        status_code=302,
    )


@router.post("/oauth-v21/token")
async def token(request: Request) -> JSONResponse:
    """Issue OAuth 2.1 bearer tokens for the mock protected resource."""

    form_data = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
    grant_type = _form_field(form_data, "grant_type")
    client_id = _form_field(form_data, "client_id")
    client_secret = _form_field(form_data, "client_secret")
    resource = _form_field(form_data, "resource")
    expected_resource = _oauth_v21_resource(request)
    issuer = get_origin_url(request)

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
                required_token_endpoint_auth_method="none",
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

        try:
            validated_resource = validate_oauth_v21_token_resource(
                resource=resource,
                expected_resource=expected_resource,
                authorized_resource=code_record.resource,
            )
        except OAuthError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.as_response())

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
            audience=validated_resource,
            issuer=issuer,
        )
        refresh_token = None
        if REFRESH_TOKEN_GRANT_TYPE in client.grant_types:
            refresh_token = oauth_token_store.issue_refresh_token(
                client_id=client_id,
                scope=code_record.scope,
                grant_type=AUTHORIZATION_CODE_GRANT_TYPE,
                audience=validated_resource,
                issuer=issuer,
            )
        logger.info(
            "oauth token issued endpoint=%s client_id=%s grant_type=%s scope=%s "
            "audience=%s issuer=%s refresh_token_issued=%s",
            "/oauth-v21/token",
            client_id,
            AUTHORIZATION_CODE_GRANT_TYPE,
            access_token.scope,
            validated_resource,
            issuer,
            refresh_token is not None,
        )
        return JSONResponse(
            status_code=200,
            content=_token_response(
                access_token=access_token.access_token,
                scope=access_token.scope,
                audience=validated_resource,
                issuer=issuer,
                refresh_token=(
                    refresh_token.refresh_token if refresh_token is not None else None
                ),
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
                required_token_endpoint_auth_method="none",
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

        try:
            validated_resource = validate_oauth_v21_refresh_resource(
                resource=resource,
                expected_resource=expected_resource,
                authorized_resource=refresh_record.audience or expected_resource,
            )
        except OAuthError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.as_response())

        access_token = oauth_token_store.issue_access_token(
            client_id=client_id,
            scope=refresh_record.scope,
            grant_type=refresh_record.grant_type,
            audience=validated_resource,
            issuer=refresh_record.issuer or issuer,
        )
        logger.info(
            "oauth token issued endpoint=%s client_id=%s grant_type=%s scope=%s "
            "audience=%s issuer=%s refresh_token_issued=%s",
            "/oauth-v21/token",
            client_id,
            REFRESH_TOKEN_GRANT_TYPE,
            access_token.scope,
            validated_resource,
            access_token.issuer or issuer,
            True,
        )
        return JSONResponse(
            status_code=200,
            content=_token_response(
                access_token=access_token.access_token,
                scope=access_token.scope,
                audience=validated_resource,
                issuer=access_token.issuer or issuer,
                refresh_token=refresh_record.refresh_token,
            ),
        )

    error = OAuthError(
        error="unsupported_grant_type",
        description="grant_type must be authorization_code or refresh_token",
        status_code=400,
    )
    return JSONResponse(status_code=error.status_code, content=error.as_response())


@router.post("/mcp/oauth-v21")
async def oauth_v21_endpoint(request: Request) -> Response:
    """Require an OAuth 2.1 token scoped to this protected resource."""

    expected_resource = _oauth_v21_resource(request)
    expected_issuer = get_origin_url(request)

    try:
        token_record = validate_access_token_header(request.headers.get("authorization"))
        validate_access_token_grant_type(
            token_record,
            expected_grant_type=AUTHORIZATION_CODE_GRANT_TYPE,
        )
        validate_access_token_audience(
            token_record,
            expected_audience=expected_resource,
        )
        validate_access_token_issuer(
            token_record,
            expected_issuer=expected_issuer,
        )
    except BearerAuthError as exc:
        return JSONResponse(
            status_code=401,
            content={"detail": exc.description},
            headers={
                "WWW-Authenticate": exc.to_www_authenticate(
                    resource_metadata=_oauth_v21_resource_metadata_url(request),
                )
            },
        )

    source_ip = request.client.host if request.client is not None else "-"
    audit_context = RequestAuditContext(
        endpoint="/mcp/oauth-v21",
        auth_scheme="oauth2.1",
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
