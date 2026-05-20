"""OAuth 2.1-specific helpers for the mock authorization server."""

from __future__ import annotations

from dataclasses import dataclass

from mcp_auth_test_server.auth.oauth import (
    DEFAULT_OAUTH_SCOPE,
    OAuthError,
    validate_scope,
)


@dataclass(slots=True)
class OAuth21AuthorizationRequest:
    """Validated OAuth 2.1 authorization request parameters."""

    response_type: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str | None
    resource: str
    code_challenge: str
    code_challenge_method: str


def validate_oauth_v21_authorization_request(
    query_params: dict[str, str | None],
    *,
    expected_resource: str,
) -> OAuth21AuthorizationRequest:
    """Validate an OAuth 2.1 authorization request."""

    response_type = query_params.get("response_type")
    client_id = query_params.get("client_id")
    redirect_uri = query_params.get("redirect_uri")
    scope = query_params.get("scope") or DEFAULT_OAUTH_SCOPE
    state = query_params.get("state")
    resource = query_params.get("resource")
    code_challenge = query_params.get("code_challenge")
    code_challenge_method = query_params.get("code_challenge_method")

    if response_type == "token":
        raise OAuthError(
            error="unsupported_response_type",
            description="implicit grant is not supported",
            status_code=400,
        )
    if response_type != "code":
        raise OAuthError(
            error="unsupported_response_type",
            description="response_type must be code",
            status_code=400,
        )
    if not client_id:
        raise OAuthError(
            error="invalid_request",
            description="client_id is required",
            status_code=400,
        )
    if not redirect_uri:
        raise OAuthError(
            error="invalid_request",
            description="redirect_uri is required",
            status_code=400,
        )
    if not resource:
        raise OAuthError(
            error="invalid_target",
            description="resource is required",
            status_code=400,
        )
    if resource != expected_resource:
        raise OAuthError(
            error="invalid_target",
            description="resource is not supported",
            status_code=400,
        )
    if not code_challenge:
        raise OAuthError(
            error="invalid_request",
            description="code_challenge is required",
            status_code=400,
        )
    if code_challenge_method != "S256":
        raise OAuthError(
            error="invalid_request",
            description="code_challenge_method must be S256",
            status_code=400,
        )

    validate_scope(scope)

    return OAuth21AuthorizationRequest(
        response_type=response_type,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        resource=resource,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )


def validate_oauth_v21_token_resource(
    *,
    resource: str | None,
    expected_resource: str,
    authorized_resource: str,
) -> str:
    """Validate the token request resource parameter for OAuth 2.1."""

    if resource is None:
        raise OAuthError(
            error="invalid_target",
            description="resource is required",
            status_code=400,
        )
    if resource != expected_resource:
        raise OAuthError(
            error="invalid_target",
            description="resource is not supported",
            status_code=400,
        )
    if resource != authorized_resource:
        raise OAuthError(
            error="invalid_target",
            description="resource does not match the original authorization request",
            status_code=400,
        )
    return resource
