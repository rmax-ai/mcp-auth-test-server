"""Static bearer-token validation for mock MCP endpoints."""

from __future__ import annotations

import os

BEARER_TOKEN_ENV_VAR = "MCP_AUTH_TEST_SERVER_BEARER_TOKEN"
DEFAULT_BEARER_TOKEN = "test-bearer-token"
BEARER_REALM = "mcp-auth-test-server"


class BearerAuthError(Exception):
    """Raised when an HTTP bearer token request fails validation."""

    def __init__(
        self,
        *,
        error: str,
        description: str,
    ) -> None:
        super().__init__(description)
        self.error = error
        self.description = description

    def to_www_authenticate(self, *, resource_metadata: str | None = None) -> str:
        """Render an RFC 6750-style challenge for bearer auth failures."""

        parts = [
            f'Bearer realm="{BEARER_REALM}"',
            f'error="{self.error}"',
            f'error_description="{self.description}"',
        ]
        if resource_metadata is not None:
            parts.append(f'resource_metadata="{resource_metadata}"')
        return ", ".join(parts)


def get_expected_bearer_token() -> str:
    """Return the configured mock bearer token for the test server."""

    return os.getenv(BEARER_TOKEN_ENV_VAR, DEFAULT_BEARER_TOKEN)


def validate_bearer_token_header(
    authorization_header: str | None,
    *,
    expected_token: str | None = None,
) -> None:
    """Validate a bearer token Authorization header."""

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

    configured_token = expected_token or get_expected_bearer_token()
    if token != configured_token:
        raise BearerAuthError(
            error="invalid_token",
            description="Bearer token is invalid",
        )
