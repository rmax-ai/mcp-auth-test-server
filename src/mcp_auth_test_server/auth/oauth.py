"""OAuth 2.0 auth-code and PKCE helpers for mock test endpoints."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from urllib.parse import urlencode

from mcp_auth_test_server.auth.bearer import BearerAuthError
from mcp_auth_test_server.auth.token_store import AccessTokenRecord, oauth_token_store
from mcp_auth_test_server.discovery import MOCK_SCOPES

DEFAULT_OAUTH_SCOPE = MOCK_SCOPES[0]
AUTHORIZATION_CODE_GRANT_TYPE = "authorization_code"
CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials"


class OAuthError(Exception):
    """Structured OAuth error for endpoint responses."""

    def __init__(
        self,
        *,
        error: str,
        description: str,
        status_code: int,
    ) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status_code = status_code

    def as_response(self) -> dict[str, str]:
        return {
            "error": self.error,
            "error_description": self.description,
        }


@dataclass(slots=True)
class AuthorizationRequest:
    """Validated OAuth authorization request parameters."""

    response_type: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str | None
    code_challenge: str
    code_challenge_method: str


def validate_authorization_request(query_params: dict[str, str | None]) -> AuthorizationRequest:
    """Validate required query parameters for the auth-code flow."""

    response_type = query_params.get("response_type")
    client_id = query_params.get("client_id")
    redirect_uri = query_params.get("redirect_uri")
    code_challenge = query_params.get("code_challenge")
    code_challenge_method = query_params.get("code_challenge_method")
    scope = query_params.get("scope") or DEFAULT_OAUTH_SCOPE
    state = query_params.get("state")

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

    return AuthorizationRequest(
        response_type=response_type,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )


def validate_scope(scope: str) -> None:
    """Ensure all requested scopes are supported by the mock AS."""

    requested_scopes = set(scope.split())
    unsupported_scopes = requested_scopes.difference(MOCK_SCOPES)
    if unsupported_scopes:
        unsupported = ", ".join(sorted(unsupported_scopes))
        raise OAuthError(
            error="invalid_scope",
            description=f"Unsupported scopes: {unsupported}",
            status_code=400,
        )


def build_redirect_uri(
    redirect_uri: str,
    *,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> str:
    """Build the redirect target for authorize success or failure."""

    params: dict[str, str] = {}
    if code is not None:
        params["code"] = code
    if state is not None:
        params["state"] = state
    if error is not None:
        params["error"] = error
    separator = "&" if "?" in redirect_uri else "?"
    return f"{redirect_uri}{separator}{urlencode(params)}"


def verify_pkce_code_verifier(*, code_verifier: str, code_challenge: str) -> bool:
    """Return True when the verifier hashes to the expected S256 challenge."""

    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return encoded == code_challenge


def validate_access_token_header(authorization_header: str | None) -> AccessTokenRecord:
    """Validate a bearer access token issued by the mock OAuth AS."""

    if authorization_header is None:
        raise BearerAuthError(
            error="invalid_request",
            description="Missing Authorization header",
        )

    scheme, _, token = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise BearerAuthError(
            error="invalid_request",
            description="Authorization header must use Bearer token auth",
        )

    record = oauth_token_store.get_access_token(token)
    if record is None:
        raise BearerAuthError(
            error="invalid_token",
            description="Bearer token is invalid",
        )
    return record


def validate_access_token_grant_type(
    record: AccessTokenRecord,
    *,
    expected_grant_type: str,
) -> None:
    """Ensure the access token was issued from the expected OAuth grant."""

    if record.grant_type != expected_grant_type:
        raise BearerAuthError(
            error="invalid_token",
            description=f"Bearer token must be issued via {expected_grant_type}",
        )
