"""RFC 7591 dynamic client registration for the mock OAuth server."""

from __future__ import annotations

import logging
from secrets import token_urlsafe

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from mcp_auth_test_server.auth.oauth import (
    AUTHORIZATION_CODE_GRANT_TYPE,
    CLIENT_CREDENTIALS_GRANT_TYPE,
    REFRESH_TOKEN_GRANT_TYPE,
    OAuthError,
    validate_scope,
)
from mcp_auth_test_server.auth.token_store import ClientRecord, oauth_token_store
from mcp_auth_test_server.discovery import MOCK_REGISTRATION_ENDPOINT_PATH

logger = logging.getLogger("mcp_auth_test_server.audit")

SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS = {"none", "client_secret_post"}
SUPPORTED_GRANT_TYPES = {
    AUTHORIZATION_CODE_GRANT_TYPE,
    CLIENT_CREDENTIALS_GRANT_TYPE,
    REFRESH_TOKEN_GRANT_TYPE,
}
SUPPORTED_RESPONSE_TYPES = {"code"}

router = APIRouter()


def _string_list(payload: dict[str, object], field: str) -> list[str] | None:
    value = payload.get(field)
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise OAuthError(
            error="invalid_client_metadata",
            description=f"{field} must be an array of strings",
            status_code=400,
        )
    return value


def _string_field(payload: dict[str, object], field: str) -> str | None:
    value = payload.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise OAuthError(
            error="invalid_client_metadata",
            description=f"{field} must be a string",
            status_code=400,
        )
    return value


def register_dynamic_client(payload: dict[str, object]) -> ClientRecord:
    """Validate mock registration metadata and persist a client record."""

    token_endpoint_auth_method = (
        _string_field(payload, "token_endpoint_auth_method") or "none"
    )
    if token_endpoint_auth_method not in SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS:
        raise OAuthError(
            error="invalid_client_metadata",
            description="token_endpoint_auth_method is not supported",
            status_code=400,
        )

    grant_types = _string_list(payload, "grant_types")
    if grant_types is None:
        grant_types = [AUTHORIZATION_CODE_GRANT_TYPE]
    unsupported_grants = sorted(set(grant_types).difference(SUPPORTED_GRANT_TYPES))
    if unsupported_grants:
        raise OAuthError(
            error="invalid_client_metadata",
            description=f"unsupported grant_types: {', '.join(unsupported_grants)}",
            status_code=400,
        )
    if (
        REFRESH_TOKEN_GRANT_TYPE in grant_types
        and AUTHORIZATION_CODE_GRANT_TYPE not in grant_types
    ):
        raise OAuthError(
            error="invalid_client_metadata",
            description="refresh_token requires authorization_code",
            status_code=400,
        )

    response_types = _string_list(payload, "response_types")
    if response_types is None:
        response_types = ["code"] if AUTHORIZATION_CODE_GRANT_TYPE in grant_types else []
    unsupported_response_types = sorted(set(response_types).difference(SUPPORTED_RESPONSE_TYPES))
    if unsupported_response_types:
        raise OAuthError(
            error="invalid_client_metadata",
            description=f"unsupported response_types: {', '.join(unsupported_response_types)}",
            status_code=400,
        )

    redirect_uris = _string_list(payload, "redirect_uris") or []
    if AUTHORIZATION_CODE_GRANT_TYPE in grant_types and not redirect_uris:
        raise OAuthError(
            error="invalid_redirect_uri",
            description="redirect_uris is required for authorization_code clients",
            status_code=400,
        )
    if AUTHORIZATION_CODE_GRANT_TYPE not in grant_types and redirect_uris:
        raise OAuthError(
            error="invalid_client_metadata",
            description="redirect_uris is only supported for authorization_code clients",
            status_code=400,
        )
    if AUTHORIZATION_CODE_GRANT_TYPE in grant_types and "code" not in response_types:
        raise OAuthError(
            error="invalid_client_metadata",
            description="response_types must include code for authorization_code clients",
            status_code=400,
        )
    if AUTHORIZATION_CODE_GRANT_TYPE not in grant_types and response_types:
        raise OAuthError(
            error="invalid_client_metadata",
            description="response_types must be empty when authorization_code is not enabled",
            status_code=400,
        )
    if (
        CLIENT_CREDENTIALS_GRANT_TYPE in grant_types
        and token_endpoint_auth_method != "client_secret_post"
    ):
        raise OAuthError(
            error="invalid_client_metadata",
            description="client_credentials requires token_endpoint_auth_method client_secret_post",
            status_code=400,
        )

    client_name = _string_field(payload, "client_name")
    scope = _string_field(payload, "scope") or "mcp:read"
    validate_scope(scope)

    client_secret = None
    if token_endpoint_auth_method == "client_secret_post":
        client_secret = f"secret-{token_urlsafe(18)}"

    return oauth_token_store.register_client(
        token_endpoint_auth_method=token_endpoint_auth_method,
        grant_types=grant_types,
        response_types=response_types,
        redirect_uris=redirect_uris,
        scope=scope,
        client_name=client_name,
        client_secret=client_secret,
    )


def validate_registered_authorization_client(
    *,
    client_id: str,
    redirect_uri: str,
    required_token_endpoint_auth_method: str | None = None,
) -> ClientRecord:
    """Ensure the client exists and may start an auth-code flow."""

    client = oauth_token_store.get_client(client_id)
    if client is None:
        raise OAuthError(
            error="invalid_client",
            description="client is not registered",
            status_code=400,
        )
    if AUTHORIZATION_CODE_GRANT_TYPE not in client.grant_types:
        raise OAuthError(
            error="unauthorized_client",
            description="client is not authorized for authorization_code",
            status_code=400,
        )
    if "code" not in client.response_types:
        raise OAuthError(
            error="unauthorized_client",
            description="client is not authorized for response_type code",
            status_code=400,
        )
    if redirect_uri not in client.redirect_uris:
        raise OAuthError(
            error="invalid_request",
            description="redirect_uri is not registered for this client",
            status_code=400,
        )
    if (
        required_token_endpoint_auth_method is not None
        and client.token_endpoint_auth_method != required_token_endpoint_auth_method
    ):
        raise OAuthError(
            error="unauthorized_client",
            description=(
                "client is not authorized for this authorization server "
                "token_endpoint_auth_method policy"
            ),
            status_code=400,
        )
    return client


def validate_registered_token_client(
    *,
    client_id: str,
    grant_type: str,
    client_secret: str | None,
    required_token_endpoint_auth_method: str | None = None,
) -> ClientRecord:
    """Ensure the client exists and may call the token endpoint for the grant."""

    client = oauth_token_store.get_client(client_id)
    if client is None:
        raise OAuthError(
            error="invalid_client",
            description="client is not registered",
            status_code=401,
        )
    if grant_type not in client.grant_types:
        raise OAuthError(
            error="unauthorized_client",
            description=f"client is not authorized for {grant_type}",
            status_code=400,
        )
    if (
        required_token_endpoint_auth_method is not None
        and client.token_endpoint_auth_method != required_token_endpoint_auth_method
    ):
        raise OAuthError(
            error="unauthorized_client",
            description=(
                "client is not authorized for this authorization server "
                "token_endpoint_auth_method policy"
            ),
            status_code=400,
        )

    if client.token_endpoint_auth_method == "none":
        if client_secret:
            raise OAuthError(
                error="invalid_request",
                description="client_secret must not be supplied for public clients",
                status_code=400,
            )
        return client

    if client.token_endpoint_auth_method == "client_secret_post":
        if not client_secret or not oauth_token_store.is_valid_client_credentials(
            client_id=client_id,
            client_secret=client_secret,
        ):
            raise OAuthError(
                error="invalid_client",
                description="client credentials are invalid",
                status_code=401,
            )
        return client

    raise OAuthError(
        error="invalid_client",
        description="client authentication method is not supported",
        status_code=401,
    )


def registration_response(client: ClientRecord) -> dict[str, object]:
    """Render a registered client in RFC 7591-style response shape."""

    response: dict[str, object] = {
        "client_id": client.client_id,
        "client_id_issued_at": client.client_id_issued_at,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "grant_types": list(client.grant_types),
        "response_types": list(client.response_types),
        "scope": client.scope,
    }
    if client.redirect_uris:
        response["redirect_uris"] = list(client.redirect_uris)
    if client.client_name is not None:
        response["client_name"] = client.client_name
    if client.client_secret is not None:
        response["client_secret"] = client.client_secret
        response["client_secret_expires_at"] = client.client_secret_expires_at
    return response


@router.post(MOCK_REGISTRATION_ENDPOINT_PATH)
async def register_client(request: Request) -> JSONResponse:
    """Register a mock OAuth client for later authorization or token calls."""

    try:
        payload = await request.json()
    except ValueError:
        error = OAuthError(
            error="invalid_client_metadata",
            description="request body must be valid JSON",
            status_code=400,
        )
        return JSONResponse(status_code=error.status_code, content=error.as_response())

    if not isinstance(payload, dict):
        error = OAuthError(
            error="invalid_client_metadata",
            description="request body must be a JSON object",
            status_code=400,
        )
        return JSONResponse(status_code=error.status_code, content=error.as_response())

    try:
        client = register_dynamic_client(payload)
    except OAuthError as exc:
        return JSONResponse(status_code=exc.status_code, content=exc.as_response())

    logger.info(
        "oauth client registered endpoint=%s client_id=%s client_name=%s auth_method=%s "
        "grant_types=%s redirect_uri_count=%s scope=%s",
        MOCK_REGISTRATION_ENDPOINT_PATH,
        client.client_id,
        client.client_name or "-",
        client.token_endpoint_auth_method,
        list(client.grant_types),
        len(client.redirect_uris),
        client.scope,
    )

    return JSONResponse(status_code=201, content=registration_response(client))
