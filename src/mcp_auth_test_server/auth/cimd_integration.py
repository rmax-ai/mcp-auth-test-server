"""Helpers that register resolved CIMD clients into the shared token store."""

from __future__ import annotations

from urllib.parse import urlsplit

from mcp_auth_test_server.auth.cimd_resolver import ClientMetadataResolver
from mcp_auth_test_server.auth.token_store import ClientRecord, oauth_token_store
from mcp_auth_test_server.auth.trace_logger import OAuthTraceEvent, trace_logger

_resolved_cimd_clients: set[str] = set()


def is_cimd_client_id(client_id: str) -> bool:
    """Return True when the client_id looks like a URL-based client identifier."""

    parsed = urlsplit(client_id)
    return bool(parsed.scheme and parsed.netloc)


def resolve_cimd_client(client_id: str, dev_mode: bool = False) -> ClientRecord | None:
    """Resolve a URL-based client ID and register it in the token store."""

    resolver = ClientMetadataResolver(development_mode=dev_mode)
    record = resolver.resolve(client_id)
    if record is None:
        return None

    existing = oauth_token_store.get_client(record.client_id)
    if existing is not None:
        _resolved_cimd_clients.add(record.client_id)
        return existing

    registered = oauth_token_store.add_client(
        client_id=record.client_id,
        token_endpoint_auth_method=record.token_endpoint_auth_method,
        grant_types=list(record.grant_types),
        response_types=list(record.response_types),
        redirect_uris=list(record.redirect_uris),
        scope=record.scope,
        client_name=record.client_name,
        client_secret=record.client_secret,
    )
    _resolved_cimd_clients.add(record.client_id)
    trace_logger.record(
        OAuthTraceEvent(
            event_type="authorize_request_validation",
            client_id=record.client_id,
            detail="registered CIMD client in token store",
            result="success",
            metadata={"cimd_resolved": True},
        )
    )
    return registered


class CimdAuthFlow:
    """Resolve and validate URL-based clients for the shared auth-code flow."""

    def __init__(self, resolver: ClientMetadataResolver | None = None) -> None:
        self._resolver = resolver or ClientMetadataResolver()

    def resolve_and_validate(self, client_id: str) -> ClientRecord | None:
        """Resolve a client ID and return the resolved record if valid."""

        return self._resolver.resolve(client_id)

    def validate_redirect_uri(self, client: ClientRecord, redirect_uri: str) -> bool:
        """Return True when the redirect URI matches the resolved metadata."""

        is_valid = redirect_uri in client.redirect_uris
        if not is_valid:
            trace_logger.record(
                OAuthTraceEvent(
                    event_type="authorize_redirect_uri_mismatch",
                    client_id=client.client_id,
                    detail="redirect_uri not present in client metadata",
                    result="failure",
                    metadata={"redirect_uri": redirect_uri},
                )
            )
        return is_valid


def ensure_cimd_client_registered(
    client_id: str,
    dev_mode: bool = False,
) -> tuple[bool, str | None]:
    """Ensure a CIMD client is available in the token store for shared validation."""

    if not is_cimd_client_id(client_id):
        return True, None

    existing = oauth_token_store.get_client(client_id)
    if existing is not None:
        _resolved_cimd_clients.add(client_id)
        return True, None

    record = resolve_cimd_client(client_id, dev_mode=dev_mode)
    if record is None:
        return False, "unable to resolve client metadata document"
    return True, None
