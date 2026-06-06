"""Auth strategy selection and interfaces."""

from __future__ import annotations

from dataclasses import dataclass

from mcp_auth_cli.auth.discovery import supported_auth_modes
from mcp_auth_cli.models import (
    AUTH_MODE_AUTH_CODE,
    AUTH_MODE_BEARER,
    AUTH_MODE_CLIENT_CREDS,
    AUTH_MODE_DEVICE,
    AUTH_MODES,
    DiscoveryResult,
    Profile,
)


@dataclass(slots=True)
class LoginContext:
    resource_url: str
    scope: str | None = None
    auth_mode: str | None = None
    register: bool = False
    client_id: str | None = None
    client_secret: str | None = None
    redirect_uri: str | None = None
    listen_port: int | None = None
    open_browser: bool = False
    bearer_token: str | None = None


def select_auth_mode(
    discovery: DiscoveryResult,
    *,
    explicit_mode: str | None,
    existing_profile: Profile | None,
    client_id: str | None,
    client_secret: str | None,
) -> str:
    if explicit_mode is not None:
        if explicit_mode not in AUTH_MODES:
            raise ValueError(f"Unsupported auth mode: {explicit_mode}")
        return explicit_mode
    if existing_profile is not None and existing_profile.refresh_token:
        return existing_profile.auth_mode
    if (
        existing_profile is not None
        and existing_profile.auth_mode == AUTH_MODE_CLIENT_CREDS
        and existing_profile.client_id
        and existing_profile.client_secret
    ):
        return AUTH_MODE_CLIENT_CREDS
    if client_id and client_secret and AUTH_MODE_CLIENT_CREDS in supported_auth_modes(discovery):
        return AUTH_MODE_CLIENT_CREDS
    if AUTH_MODE_DEVICE in supported_auth_modes(discovery):
        return AUTH_MODE_DEVICE
    if AUTH_MODE_AUTH_CODE in supported_auth_modes(discovery):
        return AUTH_MODE_AUTH_CODE
    return AUTH_MODE_BEARER
