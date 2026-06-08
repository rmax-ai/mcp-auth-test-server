"""Resolve Client ID Metadata Documents with validation, SSRF protection, and caching."""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urljoin, urlsplit

import httpx

from mcp_auth_test_server.auth.oauth import DEFAULT_OAUTH_SCOPE, validate_scope
from mcp_auth_test_server.auth.token_store import ClientRecord, oauth_token_store
from mcp_auth_test_server.auth.trace_logger import OAuthTraceEvent, trace_logger

MAX_METADATA_BYTES = 64 * 1024
CACHE_TTL_SECONDS = 300
FETCH_TIMEOUT_SECONDS = 5.0
MAX_REDIRECTS = 3

logger = logging.getLogger("mcp_auth_test_server.audit")


class CimdResolverError(ValueError):
    """Base error for CIMD resolution failures."""


class CimdSsrfBlockedError(CimdResolverError):
    """Raised when a URL is blocked by SSRF validation."""


class CimdFetchError(CimdResolverError):
    """Raised when metadata fetching fails."""


class CimdValidationError(CimdResolverError):
    """Raised when fetched metadata is invalid."""


@dataclass(slots=True)
class _CacheEntry:
    record: ClientRecord
    expires_at: datetime


class AbstractClientMetadataResolver(ABC):
    """Common interface for resolving client metadata."""

    @abstractmethod
    def resolve(self, client_id: str) -> ClientRecord | None:
        """Resolve a client identifier into a client record."""

    @abstractmethod
    def clear_cache(self) -> None:
        """Drop all resolver cache entries."""


def _is_private_ip(ip_str: str) -> bool:
    """Return True when an address falls in blocked private or local ranges."""

    ip = ipaddress.ip_address(ip_str)
    blocked_networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.169.254/32"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fd00::/8"),
        ipaddress.ip_network("fe80::/10"),
    )
    return any(ip in network for network in blocked_networks)


def _is_loopback_like_host(host: str) -> bool:
    """Return True for localhost and loopback IP literals."""

    normalized = host.strip("[]").lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _resolve_host_ips(host: str) -> set[str]:
    """Resolve a host to IP strings."""

    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return {info[4][0] for info in infos}


def _validate_cimd_url(url: str, dev_mode: bool) -> str:
    """Validate a client metadata URL against scheme and SSRF rules."""

    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        raise CimdValidationError("client_id must be an absolute URL")

    if parsed.scheme != "https":
        if not (dev_mode and parsed.scheme == "http" and parsed.hostname is not None):
            raise CimdValidationError("client metadata URLs must use https")

    host = parsed.hostname
    if host is None:
        raise CimdValidationError("client metadata URL must include a hostname")

    resolved_ips = _resolve_host_ips(host)
    blocked_ips = sorted(ip for ip in resolved_ips if _is_private_ip(ip))

    if blocked_ips:
        if dev_mode and _is_loopback_like_host(host):
            logger.warning("allowing CIMD localhost URL in development mode url=%s", url)
        else:
            raise CimdSsrfBlockedError(
                f"client metadata URL resolves to blocked IPs: {', '.join(blocked_ips)}"
            )

    if dev_mode and parsed.scheme == "http":
        logger.warning("allowing non-https CIMD URL in development mode url=%s", url)

    return parsed.geturl()


def _fetch_metadata(url: str, timeout: float) -> dict[str, object]:
    """Fetch and parse a JSON metadata document with redirect and size controls."""

    current_url = url
    with httpx.Client(
        timeout=httpx.Timeout(timeout),
        headers={"Accept": "application/json"},
        follow_redirects=False,
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            try:
                response = client.get(current_url)
            except httpx.TimeoutException as exc:
                raise CimdFetchError("timed out while fetching client metadata") from exc
            except httpx.HTTPError as exc:
                raise CimdFetchError(f"failed to fetch client metadata: {exc}") from exc

            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    raise CimdFetchError("redirect response missing location header")
                current_url = urljoin(current_url, location)
                if urlsplit(current_url).scheme != "https":
                    raise CimdFetchError("redirect target must use https")
                _validate_cimd_url(current_url, dev_mode=False)
                continue

            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise CimdFetchError(
                    f"client metadata request failed with status {response.status_code}"
                ) from exc

            content_length = response.headers.get("content-length")
            if content_length is not None and int(content_length) > MAX_METADATA_BYTES:
                raise CimdFetchError("client metadata document exceeds 64KB limit")

            body = response.content
            if len(body) > MAX_METADATA_BYTES:
                raise CimdFetchError("client metadata document exceeds 64KB limit")

            try:
                payload = response.json()
            except json.JSONDecodeError as exc:
                raise CimdFetchError("client metadata document is not valid JSON") from exc
            if not isinstance(payload, dict):
                raise CimdFetchError("client metadata document must be a JSON object")
            return payload

    raise CimdFetchError("too many redirects while fetching client metadata")


class ClientMetadataResolver(AbstractClientMetadataResolver):
    """Resolve fixture and URL-based clients into ClientRecord instances."""

    def __init__(self, development_mode: bool = False) -> None:
        self._development_mode = development_mode
        self._cache: dict[str, _CacheEntry] = {}

    def clear_cache(self) -> None:
        """Remove all cached URL resolutions."""

        self._cache.clear()

    def get_from_cache(self, url: str) -> tuple[ClientRecord | None, bool]:
        """Return a cached record and whether the lookup was a cache hit."""

        entry = self._cache.get(url)
        if entry is None:
            return None, False
        if entry.expires_at <= datetime.now(UTC):
            self._cache.pop(url, None)
            return None, False
        return entry.record, True

    def resolve(self, client_id: str) -> ClientRecord | None:
        """Resolve either a fixture client ID or a CIMD URL."""

        if not urlsplit(client_id).scheme:
            return oauth_token_store.get_client(client_id)

        cached_record, cache_hit = self.get_from_cache(client_id)
        if cache_hit and cached_record is not None:
            trace_logger.record(
                OAuthTraceEvent(
                    event_type="cimd_fetch_cache_hit",
                    client_id=client_id,
                    detail="cimd_fetch_hit",
                    result="success",
                )
            )
            logger.debug("cimd_fetch_hit client_id=%s", client_id)
            return cached_record

        trace_logger.record(
            OAuthTraceEvent(
                event_type="cimd_fetch_cache_miss",
                client_id=client_id,
                detail="cimd_fetch_miss",
                result="success",
            )
        )
        logger.debug("cimd_fetch_miss client_id=%s", client_id)
        trace_logger.record(
            OAuthTraceEvent(
                event_type="cimd_fetch_start",
                client_id=client_id,
                detail="fetching client metadata",
                result="success",
            )
        )

        try:
            validated_url = _validate_cimd_url(client_id, self._development_mode)
            metadata = _fetch_metadata(validated_url, FETCH_TIMEOUT_SECONDS)
            record = self._client_record_from_metadata(validated_url, metadata)
        except CimdSsrfBlockedError as exc:
            trace_logger.record(
                OAuthTraceEvent(
                    event_type="cimd_ssrf_blocked",
                    client_id=client_id,
                    detail=str(exc),
                    result="blocked",
                )
            )
            logger.warning("cimd_ssrf_blocked client_id=%s detail=%s", client_id, exc)
            return None
        except CimdValidationError as exc:
            trace_logger.record(
                OAuthTraceEvent(
                    event_type="cimd_validation_error",
                    client_id=client_id,
                    detail=str(exc),
                    result="failure",
                )
            )
            logger.warning("cimd_validation_error client_id=%s detail=%s", client_id, exc)
            return None
        except CimdFetchError as exc:
            trace_logger.record(
                OAuthTraceEvent(
                    event_type="cimd_fetch_error",
                    client_id=client_id,
                    detail=str(exc),
                    result="failure",
                )
            )
            logger.warning("cimd_fetch_error client_id=%s detail=%s", client_id, exc)
            return None

        self._cache[validated_url] = _CacheEntry(
            record=record,
            expires_at=datetime.now(UTC) + timedelta(seconds=CACHE_TTL_SECONDS),
        )
        trace_logger.record(
            OAuthTraceEvent(
                event_type="cimd_fetch_success",
                client_id=client_id,
                detail="resolved client metadata document",
                result="success",
                metadata={"redirect_uri_count": len(record.redirect_uris)},
            )
        )
        logger.debug("cimd_fetch_success client_id=%s", client_id)
        return record

    def _client_record_from_metadata(
        self,
        resolved_url: str,
        metadata: dict[str, object],
    ) -> ClientRecord:
        """Validate fetched metadata and convert it to a ClientRecord."""

        client_id = metadata.get("client_id")
        if not isinstance(client_id, str):
            raise CimdValidationError("client metadata must include string client_id")
        if client_id != resolved_url:
            raise CimdValidationError("client metadata client_id must match fetched URL")

        redirect_uris = metadata.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris:
            raise CimdValidationError("client metadata must include redirect_uris")
        if not all(isinstance(uri, str) for uri in redirect_uris):
            raise CimdValidationError("redirect_uris must be an array of strings")
        for redirect_uri in redirect_uris:
            self._validate_redirect_uri(redirect_uri)

        grant_types = metadata.get("grant_types", ["authorization_code"])
        if not isinstance(grant_types, list) or not all(
            isinstance(item, str) for item in grant_types
        ):
            raise CimdValidationError("grant_types must be an array of strings")
        if "authorization_code" not in grant_types:
            raise CimdValidationError("authorization_code grant is required for CIMD auth flow")

        response_types = metadata.get("response_types", ["code"])
        if not isinstance(response_types, list) or not all(
            isinstance(item, str) for item in response_types
        ):
            raise CimdValidationError("response_types must be an array of strings")
        if "code" not in response_types:
            raise CimdValidationError("response_types must include code")

        token_endpoint_auth_method = metadata.get("token_endpoint_auth_method", "none")
        if token_endpoint_auth_method != "none":
            raise CimdValidationError("only token_endpoint_auth_method=none is supported")

        scope = metadata.get("scope", DEFAULT_OAUTH_SCOPE)
        if not isinstance(scope, str):
            raise CimdValidationError("scope must be a string")
        validate_scope(scope)

        client_name = metadata.get("client_name")
        if client_name is not None and not isinstance(client_name, str):
            raise CimdValidationError("client_name must be a string when provided")

        return ClientRecord(
            client_id=client_id,
            token_endpoint_auth_method=token_endpoint_auth_method,
            grant_types=tuple(grant_types),
            response_types=tuple(response_types),
            redirect_uris=tuple(redirect_uris),
            scope=scope,
            client_name=client_name,
            client_id_issued_at=int(datetime.now(UTC).timestamp()),
            client_secret=None,
            client_secret_expires_at=0,
        )

    def _validate_redirect_uri(self, redirect_uri: str) -> None:
        """Validate redirect URIs declared by the fetched metadata."""

        parsed = urlsplit(redirect_uri)
        if not parsed.scheme or not parsed.netloc:
            raise CimdValidationError("redirect_uris entries must be absolute URLs")

        host = parsed.hostname
        if host is None:
            raise CimdValidationError("redirect_uris entries must include a hostname")

        if parsed.scheme == "https":
            return
        if self._development_mode and parsed.scheme == "http" and _is_loopback_like_host(host):
            logger.warning(
                "allowing localhost redirect URI in development mode redirect_uri=%s",
                redirect_uri,
            )
            return
        raise CimdValidationError("redirect_uris must use https except localhost in development")
