"""Manual bearer-token login strategy."""

from __future__ import annotations

from uuid import uuid4

from mcp_auth_cli.errors import CliError
from mcp_auth_cli.models import AUTH_MODE_BEARER, Profile


def login_with_bearer(*, ui, resource_url: str, bearer_token: str | None) -> Profile:
    token = bearer_token or ui.prompt_secret("Bearer token")
    if not token:
        raise CliError("Bearer token is required.")
    return Profile(
        profile_id=uuid4().hex,
        resource_url=resource_url,
        auth_mode=AUTH_MODE_BEARER,
        access_token=token,
        token_type="Bearer",
    )
