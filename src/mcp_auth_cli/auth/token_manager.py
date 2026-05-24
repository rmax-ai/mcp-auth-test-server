"""Access-token maintenance helpers."""

from __future__ import annotations

from mcp_auth_cli.errors import CliError
from mcp_auth_cli.models import AUTH_MODE_CLIENT_CREDS, Profile


def ensure_valid_access_token(client, profile: Profile, *, resource_url: str, ui=None) -> Profile:
    if profile.is_access_token_valid():
        return profile
    if profile.refresh_token and profile.token_endpoint:
        if ui is not None:
            ui.step("Refreshing expired access token")
        token_payload = _post_token(
            client,
            profile.token_endpoint,
            {
                "grant_type": "refresh_token",
                "refresh_token": profile.refresh_token,
                "client_id": required(profile.client_id, "client_id"),
                "resource": resource_url,
                **(
                    {"client_secret": profile.client_secret}
                    if profile.token_endpoint_auth_method == "client_secret_post"
                    and profile.client_secret
                    else {}
                ),
            },
        )
        profile.set_token_response(token_payload)
        return profile

    if profile.auth_mode == AUTH_MODE_CLIENT_CREDS:
        if ui is not None:
            ui.step("Requesting a new client-credentials access token")
        if not profile.token_endpoint:
            raise CliError("Cannot reacquire token without a token endpoint.")
        token_payload = _post_token(
            client,
            profile.token_endpoint,
            {
                "grant_type": "client_credentials",
                "client_id": required(profile.client_id, "client_id"),
                "client_secret": required(profile.client_secret, "client_secret"),
                "scope": profile.scope or "",
                "resource": resource_url,
            },
        )
        profile.set_token_response(token_payload)
        return profile

    raise CliError("Stored credentials cannot refresh this profile. Run login again.")


def _post_token(client, token_endpoint: str, data: dict[str, str]) -> dict[str, object]:
    response = client.post(token_endpoint, data=data)
    if response.status_code >= 400:
        raise CliError(f"Token request failed: HTTP {response.status_code}: {response.text}")
    payload = response.json()
    if not isinstance(payload, dict) or "access_token" not in payload:
        raise CliError("Token endpoint returned an invalid response.")
    return payload


def required(value: str | None, field_name: str) -> str:
    if not value:
        raise CliError(f"Missing required stored field: {field_name}")
    return value
