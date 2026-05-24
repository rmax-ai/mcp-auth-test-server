"""Client credentials strategy."""

from __future__ import annotations

from uuid import uuid4

from mcp_auth_cli.errors import CliError
from mcp_auth_cli.models import AUTH_MODE_CLIENT_CREDS, AuthorizationServerMetadata, Profile


def login_with_client_credentials(
    client,
    *,
    ui,
    resource_url: str,
    auth_server: AuthorizationServerMetadata,
    scope: str | None,
    client_id: str | None,
    client_secret: str | None,
    register: bool,
) -> Profile:
    resolved_client_id = client_id
    resolved_client_secret = client_secret
    registration_payload = None

    if register:
        if auth_server.registration_endpoint is None:
            raise CliError("This authorization server does not advertise dynamic registration.")
        registration_payload = _register_client(client, auth_server, scope=scope)
        resolved_client_id = registration_payload["client_id"]
        resolved_client_secret = registration_payload.get("client_secret")
        ui.step(f"Registered confidential client {resolved_client_id}")

    if not resolved_client_id:
        resolved_client_id = ui.prompt("Client ID")
    if not resolved_client_secret:
        resolved_client_secret = ui.prompt_secret("Client secret")
    if not resolved_client_id or not resolved_client_secret:
        raise CliError("Client credentials require both client_id and client_secret.")
    if auth_server.token_endpoint is None:
        raise CliError("Authorization server metadata does not include a token endpoint.")

    data = {
        "grant_type": "client_credentials",
        "client_id": resolved_client_id,
        "client_secret": resolved_client_secret,
        "resource": resource_url,
    }
    if scope:
        data["scope"] = scope
    response = client.post(auth_server.token_endpoint, data=data)
    if response.status_code >= 400:
        raise CliError(
            f"Client credentials login failed: HTTP {response.status_code}: {response.text}"
        )
    token_payload = response.json()
    profile = Profile(
        profile_id=uuid4().hex,
        resource_url=resource_url,
        auth_mode=AUTH_MODE_CLIENT_CREDS,
        issuer=auth_server.issuer,
        authorization_server_metadata_url=auth_server.metadata_url,
        token_endpoint=auth_server.token_endpoint,
        authorization_endpoint=auth_server.authorization_endpoint,
        device_authorization_endpoint=auth_server.device_authorization_endpoint,
        registration_endpoint=auth_server.registration_endpoint,
        client_id=resolved_client_id,
        client_secret=resolved_client_secret,
        token_endpoint_auth_method="client_secret_post",
        dynamic_client_registration=registration_payload,
    )
    profile.set_token_response(token_payload)
    return profile


def _register_client(client, auth_server: AuthorizationServerMetadata, *, scope: str | None):
    payload = {
        "client_name": "mcp-auth CLI confidential client",
        "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "client_secret_post",
    }
    if scope:
        payload["scope"] = scope
    response = client.post(auth_server.registration_endpoint, json=payload)
    if response.status_code >= 400:
        raise CliError(f"Dynamic registration failed: HTTP {response.status_code}: {response.text}")
    body = response.json()
    if "client_id" not in body or "client_secret" not in body:
        raise CliError("Dynamic registration response did not contain client credentials.")
    return body
