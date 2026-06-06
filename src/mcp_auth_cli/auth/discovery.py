"""OAuth and protected resource discovery."""

from __future__ import annotations

from urllib.parse import urlencode, urlparse

from mcp_auth_cli.errors import CliError
from mcp_auth_cli.models import (
    AUTH_MODE_AUTH_CODE,
    AUTH_MODE_BEARER,
    AUTH_MODE_CLIENT_CREDS,
    AUTH_MODE_DEVICE,
    AuthorizationServerMetadata,
    DiscoveryResult,
    ProtectedResourceMetadata,
)

PROTECTED_RESOURCE_WELL_KNOWN = "/.well-known/oauth-protected-resource"
AUTHORIZATION_SERVER_WELL_KNOWN = "/.well-known/oauth-authorization-server"


def discover(
    client,
    *,
    resource_url: str,
    resource_metadata_url: str | None = None,
    authorization_server: str | None = None,
    ui=None,
) -> DiscoveryResult:
    result = DiscoveryResult(
        resource_url=resource_url,
        resource_metadata_url=resource_metadata_url,
    )
    protected_resource_url = resource_metadata_url or _resource_metadata_url(resource_url)
    result.resource_metadata_url = protected_resource_url

    if ui is not None:
        ui.detail(f"GET {protected_resource_url}")
    protected_response = client.get(protected_resource_url)
    if protected_response.status_code < 400:
        payload = protected_response.json()
        result.protected_resource_metadata = ProtectedResourceMetadata(
            resource=str(payload.get("resource", resource_url)),
            authorization_servers=list(payload.get("authorization_servers", [])),
            bearer_methods_supported=list(payload.get("bearer_methods_supported", [])),
            scopes_supported=list(payload.get("scopes_supported", [])),
            raw=payload,
        )
    else:
        result.warnings.append(
            f"Protected resource metadata unavailable: HTTP {protected_response.status_code}"
        )

    auth_server_urls = []
    if authorization_server:
        auth_server_urls.append(_normalize_auth_server_reference(authorization_server))
    elif result.protected_resource_metadata is not None:
        auth_server_urls.extend(result.protected_resource_metadata.authorization_servers)

    seen = set()
    for metadata_url in auth_server_urls:
        if metadata_url in seen:
            continue
        seen.add(metadata_url)
        if ui is not None:
            ui.detail(f"GET {metadata_url}")
        response = client.get(metadata_url)
        if response.status_code >= 400:
            result.warnings.append(
                f"Authorization server metadata unavailable at {metadata_url}: "
                f"HTTP {response.status_code}"
            )
            continue
        payload = response.json()
        result.authorization_servers.append(
            AuthorizationServerMetadata(
                metadata_url=metadata_url,
                issuer=_string_or_none(payload.get("issuer")),
                authorization_endpoint=_string_or_none(payload.get("authorization_endpoint")),
                device_authorization_endpoint=_string_or_none(
                    payload.get("device_authorization_endpoint")
                ),
                token_endpoint=_string_or_none(payload.get("token_endpoint")),
                registration_endpoint=_string_or_none(payload.get("registration_endpoint")),
                grant_types_supported=_string_list(payload.get("grant_types_supported")),
                token_endpoint_auth_methods_supported=_string_list(
                    payload.get("token_endpoint_auth_methods_supported")
                ),
                response_types_supported=_string_list(payload.get("response_types_supported")),
                scopes_supported=_string_list(payload.get("scopes_supported")),
                raw=payload,
            )
        )

    if (
        not result.authorization_servers
        and not authorization_server
        and result.protected_resource_metadata
    ):
        result.warnings.append("No authorization server metadata advertised by the resource.")
    return result


def supported_auth_modes(discovery: DiscoveryResult) -> list[str]:
    modes: list[str] = []
    if discovery.protected_resource_metadata is not None:
        if "header" in discovery.protected_resource_metadata.bearer_methods_supported:
            modes.append(AUTH_MODE_BEARER)
    for metadata in discovery.authorization_servers:
        grants = set(metadata.grant_types_supported)
        if (
            "client_credentials" in grants
            and metadata.token_endpoint is not None
            and AUTH_MODE_CLIENT_CREDS not in modes
        ):
            modes.append(AUTH_MODE_CLIENT_CREDS)
        if (
            "urn:ietf:params:oauth:grant-type:device_code" in grants
            and metadata.device_authorization_endpoint is not None
            and metadata.token_endpoint is not None
            and AUTH_MODE_DEVICE not in modes
        ):
            modes.append(AUTH_MODE_DEVICE)
        if (
            "authorization_code" in grants
            and metadata.authorization_endpoint is not None
            and metadata.token_endpoint is not None
            and AUTH_MODE_AUTH_CODE not in modes
        ):
            modes.append(AUTH_MODE_AUTH_CODE)
    if not modes:
        modes.append(AUTH_MODE_BEARER)
    return modes


def pick_authorization_server(discovery: DiscoveryResult, auth_mode: str):
    for metadata in discovery.authorization_servers:
        grants = set(metadata.grant_types_supported)
        if auth_mode == AUTH_MODE_AUTH_CODE and "authorization_code" in grants:
            return metadata
        if (
            auth_mode == AUTH_MODE_DEVICE
            and "urn:ietf:params:oauth:grant-type:device_code" in grants
        ):
            return metadata
        if auth_mode == AUTH_MODE_CLIENT_CREDS and "client_credentials" in grants:
            return metadata
    if discovery.authorization_servers:
        return discovery.authorization_servers[0]
    raise CliError("No authorization server metadata available for the selected auth mode.")


def _resource_metadata_url(resource_url: str) -> str:
    parsed = urlparse(resource_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    query = urlencode({"resource": resource_url})
    return f"{origin}{PROTECTED_RESOURCE_WELL_KNOWN}?{query}"


def _normalize_auth_server_reference(value: str) -> str:
    if "/.well-known/" in value:
        return value
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise CliError("authorization server URL must be absolute")
    return f"{parsed.scheme}://{parsed.netloc}{AUTHORIZATION_SERVER_WELL_KNOWN}"


def _string_or_none(value) -> str | None:
    return value if isinstance(value, str) else None


def _string_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]
