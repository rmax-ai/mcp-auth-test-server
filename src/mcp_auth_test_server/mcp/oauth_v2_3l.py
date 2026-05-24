"""Unified OAuth authorization server and protected MCP endpoint."""

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
    DEVICE_CODE_GRANT_TYPE,
    REFRESH_TOKEN_GRANT_TYPE,
    OAuthError,
    build_redirect_uri,
    validate_access_token_audience,
    validate_access_token_header,
    validate_access_token_issuer,
    validate_authorization_request,
    validate_refresh_resource,
    validate_scope,
    validate_token_resource,
    verify_pkce_code_verifier,
)
from mcp_auth_test_server.auth.token_store import (
    ACCESS_TOKEN_TTL_SECONDS,
    DEVICE_CODE_INTERVAL_SECONDS,
    DEVICE_CODE_TTL_SECONDS,
    oauth_token_store,
)
from mcp_auth_test_server.discovery import (
    OAUTH_RESOURCE_PATH,
    PROTECTED_RESOURCE_METADATA_PATH,
    build_absolute_url,
    build_discovery_url,
    get_origin_url,
)
from mcp_auth_test_server.mcp.base import (
    BaseMCPHandler,
    RequestAuditContext,
    handle_mcp_request,
)
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

router = APIRouter()
logger = logging.getLogger("mcp_auth_test_server.audit")

handler = BaseMCPHandler(
    server_name="mcp-auth-test-server",
    server_version="0.1.0",
    instructions=(
        "This endpoint requires an OAuth bearer token for this protected resource. "
        "Supported grants include authorization code + PKCE, client credentials, "
        "and device authorization."
    ),
    tools=get_core_tools(),
)


def _form_field(form_data: dict[str, list[str]], name: str) -> str | None:
    values = form_data.get(name)
    if not values:
        return None
    return values[0]


def _oauth_resource(request: Request) -> str:
    return build_absolute_url(request, OAUTH_RESOURCE_PATH)


def _oauth_resource_metadata_url(request: Request) -> str:
    return build_discovery_url(
        request,
        PROTECTED_RESOURCE_METADATA_PATH,
        resource=_oauth_resource(request),
    )


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
    <title>Authorize MCP Test Client</title>
  </head>
  <body>
    <h1>Mock OAuth Consent</h1>
    <p>
      Client <strong>{client_id}</strong> is requesting access to scope
      <strong>{scope}</strong> for resource <strong>{resource}</strong>.
    </p>
    <form method="post" action="/oauth/authorize/consent">
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


@router.get(
    "/oauth/authorize",
    tags=["Auth: OAuth"],
    responses=AUTHORIZE_RESPONSES,
    openapi_extra={"parameters": AUTHORIZE_PARAMETERS},
)
async def authorize(request: Request) -> Response:
    """Render mock consent for a valid authorization request."""

    issuer = get_origin_url(request)
    expected_resource = _oauth_resource(request)

    try:
        auth_request = validate_authorization_request(
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
        )
    )


@router.post(
    "/oauth/authorize/consent",
    tags=["Auth: OAuth"],
    responses={
        302: {"description": "Redirect back to the client with either `code` or `error`."},
        400: OAUTH_ERROR_RESPONSE,
    },
    openapi_extra=AUTHORIZE_CONSENT_REQUEST_BODY,
)
async def authorize_consent(request: Request) -> Response:
    """Simulate browser consent and redirect with code or error."""

    form_data = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
    issuer = get_origin_url(request)
    expected_resource = _oauth_resource(request)

    try:
        auth_request = validate_authorization_request(
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


@router.post(
    "/oauth/token",
    tags=["Auth: OAuth"],
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
    resource = _form_field(form_data, "resource")
    expected_resource = _oauth_resource(request)
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
            validated_resource = validate_token_resource(
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
            "/oauth/token",
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

        try:
            validated_resource = validate_refresh_resource(
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
            "/oauth/token",
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
            validate_scope(requested_scope)
        except OAuthError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.as_response())

        access_token = oauth_token_store.issue_access_token(
            client_id=client_id,
            scope=requested_scope,
            grant_type=CLIENT_CREDENTIALS_GRANT_TYPE,
            audience=expected_resource,
            issuer=issuer,
        )
        logger.info(
            "oauth token issued endpoint=%s client_id=%s grant_type=%s scope=%s "
            "audience=%s issuer=%s refresh_token_issued=%s",
            "/oauth/token",
            client_id,
            CLIENT_CREDENTIALS_GRANT_TYPE,
            access_token.scope,
            expected_resource,
            issuer,
            False,
        )
        return JSONResponse(
            status_code=200,
            content=_token_response(
                access_token=access_token.access_token,
                scope=access_token.scope,
                audience=expected_resource,
                issuer=issuer,
            ),
        )

    if grant_type == DEVICE_CODE_GRANT_TYPE:
        device_code = _form_field(form_data, "device_code")

        if not client_id or not device_code:
            error = OAuthError(
                error="invalid_request",
                description="client_id and device_code are required",
                status_code=400,
            )
            return JSONResponse(status_code=error.status_code, content=error.as_response())

        try:
            client = validate_registered_token_client(
                client_id=client_id,
                grant_type=DEVICE_CODE_GRANT_TYPE,
                client_secret=client_secret,
            )
        except OAuthError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.as_response())

        code_record = oauth_token_store.get_device_code(device_code)
        if code_record is None:
            consumed = oauth_token_store.consume_device_code(device_code, client_id)
            if consumed is None:
                error = OAuthError(
                    error="expired_token",
                    description="device code has expired",
                    status_code=400,
                )
                return JSONResponse(status_code=error.status_code, content=error.as_response())
            access_token = oauth_token_store.issue_access_token(
                client_id=client_id,
                scope=consumed.scope,
                grant_type=DEVICE_CODE_GRANT_TYPE,
                audience=expected_resource,
                issuer=issuer,
            )
            refresh_token = None
            if REFRESH_TOKEN_GRANT_TYPE in client.grant_types:
                refresh_token = oauth_token_store.issue_refresh_token(
                    client_id=client_id,
                    scope=consumed.scope,
                    grant_type=DEVICE_CODE_GRANT_TYPE,
                    audience=expected_resource,
                    issuer=issuer,
                )
            return JSONResponse(
                status_code=200,
                content=_token_response(
                    access_token=access_token.access_token,
                    scope=access_token.scope,
                    audience=expected_resource,
                    issuer=issuer,
                    refresh_token=(
                        refresh_token.refresh_token if refresh_token is not None else None
                    ),
                ),
            )

        if not code_record.verified:
            error = OAuthError(
                error="authorization_pending",
                description="device code has not been verified yet",
                status_code=400,
            )
            return JSONResponse(status_code=error.status_code, content=error.as_response())

        consumed = oauth_token_store.consume_device_code(device_code, client_id)
        if consumed is None:
            error = OAuthError(
                error="expired_token",
                description="device code has expired",
                status_code=400,
            )
            return JSONResponse(status_code=error.status_code, content=error.as_response())

        access_token = oauth_token_store.issue_access_token(
            client_id=client_id,
            scope=consumed.scope,
            grant_type=DEVICE_CODE_GRANT_TYPE,
            audience=expected_resource,
            issuer=issuer,
        )
        refresh_token = None
        if REFRESH_TOKEN_GRANT_TYPE in client.grant_types:
            refresh_token = oauth_token_store.issue_refresh_token(
                client_id=client_id,
                scope=consumed.scope,
                grant_type=DEVICE_CODE_GRANT_TYPE,
                audience=expected_resource,
                issuer=issuer,
            )
        logger.info(
            "oauth token issued endpoint=%s client_id=%s grant_type=%s scope=%s "
            "audience=%s issuer=%s refresh_token_issued=%s",
            "/oauth/token",
            client_id,
            DEVICE_CODE_GRANT_TYPE,
            access_token.scope,
            expected_resource,
            issuer,
            refresh_token is not None,
        )
        return JSONResponse(
            status_code=200,
            content=_token_response(
                access_token=access_token.access_token,
                scope=access_token.scope,
                audience=expected_resource,
                issuer=issuer,
                refresh_token=(
                    refresh_token.refresh_token if refresh_token is not None else None
                ),
            ),
        )

    error = OAuthError(
        error="unsupported_grant_type",
        description=(
            "grant_type must be authorization_code, refresh_token, "
            "client_credentials, or device_code"
        ),
        status_code=400,
    )
    return JSONResponse(status_code=error.status_code, content=error.as_response())


@router.post(
    "/oauth/device/authorize",
    tags=["Auth: OAuth"],
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


@router.get("/oauth/device/verify", tags=["Auth: OAuth"])
async def device_verify(user_code: str | None = None) -> HTMLResponse:
    """Render the device verification page with an optional pre-filled user code."""

    return HTMLResponse(_render_verify_page(user_code=user_code))


@router.post("/oauth/device/verify/consent", tags=["Auth: OAuth"])
async def device_verify_consent(request: Request) -> HTMLResponse:
    """Process device verification consent."""

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
    OAUTH_RESOURCE_PATH,
    tags=["MCP Endpoints"],
    responses={
        **MCP_RESPONSES,
        401: UNAUTHORIZED_RESPONSE,
    },
    openapi_extra=MCP_REQUEST_BODY,
)
async def oauth_endpoint(request: Request) -> Response:
    """Require an OAuth token scoped to the canonical protected resource."""

    expected_resource = _oauth_resource(request)
    expected_issuer = get_origin_url(request)

    try:
        token_record = validate_access_token_header(request.headers.get("authorization"))
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
                    resource_metadata=_oauth_resource_metadata_url(request),
                )
            },
        )

    source_ip = request.client.host if request.client is not None else "-"
    audit_context = RequestAuditContext(
        endpoint=OAUTH_RESOURCE_PATH,
        auth_scheme="oauth2",
        caller=token_record.client_id,
        source_ip=source_ip,
        client_id=token_record.client_id,
        scope=token_record.scope,
        grant_type=token_record.grant_type,
        audience=token_record.audience or "-",
        issuer=token_record.issuer or "-",
    )
    return await handle_mcp_request(
        request,
        handler=handler,
        audit_context=audit_context,
    )
