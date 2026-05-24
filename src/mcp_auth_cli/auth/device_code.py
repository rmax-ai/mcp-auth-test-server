"""OAuth device authorization strategy."""

from __future__ import annotations

import time
from uuid import uuid4

from mcp_auth_cli.errors import CliError
from mcp_auth_cli.models import (
    AUTH_MODE_DEVICE,
    DEVICE_CODE_GRANT_TYPE,
    AuthorizationServerMetadata,
    Profile,
)


def login_with_device_code(
    client,
    *,
    ui,
    resource_url: str,
    auth_server: AuthorizationServerMetadata,
    scope: str | None,
    client_id: str | None,
    register: bool,
    max_polls: int = 30,
) -> Profile:
    resolved_client_id = client_id
    registration_payload = None
    if register:
        if auth_server.registration_endpoint is None:
            raise CliError("This authorization server does not advertise dynamic registration.")
        registration_payload = _register_client(client, auth_server, scope=scope)
        resolved_client_id = registration_payload["client_id"]
        ui.step(f"Registered device client {resolved_client_id}")
    if not resolved_client_id:
        resolved_client_id = ui.prompt("Client ID")
    if not resolved_client_id:
        raise CliError("Device flow requires a client_id.")
    if auth_server.device_authorization_endpoint is None or auth_server.token_endpoint is None:
        raise CliError("Authorization server metadata is missing required device endpoints.")

    authorize_response = client.post(
        auth_server.device_authorization_endpoint,
        data={
            "client_id": resolved_client_id,
            **({"scope": scope} if scope else {}),
        },
    )
    if authorize_response.status_code >= 400:
        raise CliError(
            f"Device authorization failed: HTTP {authorize_response.status_code}: "
            f"{authorize_response.text}"
        )
    device_payload = authorize_response.json()
    verification_uri = str(device_payload.get("verification_uri", ""))
    user_code = str(device_payload.get("user_code", ""))
    complete_uri = str(device_payload.get("verification_uri_complete", verification_uri))
    interval = int(device_payload.get("interval", 5))

    ui.step("Device authorization started")
    ui.info(f"Visit: {verification_uri}")
    ui.info(f"User code: {user_code}")
    if complete_uri:
        ui.detail(f"Verification URI complete: {complete_uri}")
    ui.step("Waiting for device approval")

    data = {
        "grant_type": DEVICE_CODE_GRANT_TYPE,
        "client_id": resolved_client_id,
        "device_code": str(device_payload.get("device_code", "")),
    }
    for _ in range(max_polls):
        token_response = client.post(auth_server.token_endpoint, data=data)
        if token_response.status_code < 400:
            token_payload = token_response.json()
            profile = Profile(
                profile_id=uuid4().hex,
                resource_url=resource_url,
                auth_mode=AUTH_MODE_DEVICE,
                issuer=auth_server.issuer,
                authorization_server_metadata_url=auth_server.metadata_url,
                token_endpoint=auth_server.token_endpoint,
                authorization_endpoint=auth_server.authorization_endpoint,
                device_authorization_endpoint=auth_server.device_authorization_endpoint,
                registration_endpoint=auth_server.registration_endpoint,
                client_id=resolved_client_id,
                token_endpoint_auth_method="none",
                dynamic_client_registration=registration_payload,
            )
            profile.set_token_response(token_payload)
            return profile
        error_payload = token_response.json()
        error_code = error_payload.get("error")
        if error_code == "authorization_pending":
            time.sleep(interval)
            continue
        if error_code == "slow_down":
            interval += 1
            time.sleep(interval)
            continue
        if error_code == "access_denied":
            raise CliError("Device authorization was denied.")
        if error_code == "expired_token":
            raise CliError("Device code expired before authorization completed.")
        raise CliError(f"Device token request failed: {token_response.text}")
    raise CliError("Device authorization timed out.")


def _register_client(client, auth_server: AuthorizationServerMetadata, *, scope: str | None):
    payload = {
        "client_name": "mcp-auth CLI device client",
        "grant_types": [DEVICE_CODE_GRANT_TYPE, "refresh_token"],
        "token_endpoint_auth_method": "none",
    }
    if scope:
        payload["scope"] = scope
    response = client.post(auth_server.registration_endpoint, json=payload)
    if response.status_code >= 400:
        raise CliError(f"Dynamic registration failed: HTTP {response.status_code}: {response.text}")
    body = response.json()
    if "client_id" not in body:
        raise CliError("Dynamic registration response did not contain a client_id.")
    return body
