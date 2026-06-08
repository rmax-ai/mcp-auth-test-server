"""Tests for URL-based CIMD client metadata resolution."""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from mcp_auth_test_server.auth.cimd_integration import CimdAuthFlow
from mcp_auth_test_server.auth.cimd_resolver import (
    CimdFetchError,
    CimdResolverError,
    CimdValidationError,
    ClientMetadataResolver,
    _fetch_metadata,
    _is_private_ip,
    _validate_cimd_url,
)
from mcp_auth_test_server.auth.trace_logger import trace_logger


class FakeClient:
    def __init__(self, handler: Callable[[str], httpx.Response | Exception]) -> None:
        self._handler = handler

    def __enter__(self) -> FakeClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def get(self, url: str) -> httpx.Response:
        response_or_error = self._handler(url)
        if isinstance(response_or_error, Exception):
            raise response_or_error
        return response_or_error


def _response(
    url: str,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    json_body: dict[str, object] | None = None,
    content: bytes | None = None,
) -> httpx.Response:
    if json_body is not None:
        content = json.dumps(json_body).encode("utf-8")
        response_headers = {"content-type": "application/json"}
    else:
        response_headers = {}
    if headers is not None:
        response_headers.update(headers)
    return httpx.Response(
        status_code=status_code,
        headers=response_headers,
        content=content or b"",
        request=httpx.Request("GET", url),
    )


def _patch_dns(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[str]]) -> None:
    def fake_getaddrinfo(host: str, port: int | None, type: int = 0):  # noqa: A002
        return [(0, 0, 0, "", (ip, 0)) for ip in mapping[host]]

    from mcp_auth_test_server.auth import cimd_resolver

    module = cimd_resolver
    monkeypatch.setattr(module.socket, "getaddrinfo", fake_getaddrinfo)


def _patch_http_client(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[str], httpx.Response | Exception],
) -> None:
    from mcp_auth_test_server.auth import cimd_resolver

    module = cimd_resolver
    monkeypatch.setattr(module.httpx, "Client", lambda **kwargs: FakeClient(handler))


@pytest.fixture(autouse=True)
def clear_trace_logger() -> None:
    trace_logger.clear()
    yield
    trace_logger.clear()


def test_reject_non_https_urls(monkeypatch: pytest.MonkeyPatch):
    _patch_dns(monkeypatch, {"client.example": ["203.0.113.10"]})

    with pytest.raises(CimdValidationError, match="https"):
        _validate_cimd_url("http://client.example/metadata.json", dev_mode=False)


def test_reject_private_ip(monkeypatch: pytest.MonkeyPatch):
    _patch_dns(monkeypatch, {"private.example": ["10.0.0.8"]})

    with pytest.raises(CimdResolverError, match="blocked IPs"):
        _validate_cimd_url("https://private.example/metadata.json", dev_mode=False)


def test_reject_localhost_in_production(monkeypatch: pytest.MonkeyPatch):
    _patch_dns(monkeypatch, {"localhost": ["127.0.0.1"]})

    with pytest.raises(CimdResolverError, match="blocked IPs"):
        _validate_cimd_url("https://localhost/metadata.json", dev_mode=False)


def test_allow_localhost_in_dev_mode(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    _patch_dns(monkeypatch, {"localhost": ["127.0.0.1"]})

    validated = _validate_cimd_url("http://localhost/metadata.json", dev_mode=True)

    assert validated == "http://localhost/metadata.json"
    assert "allowing CIMD localhost URL in development mode" in caplog.text


def test_reject_link_local(monkeypatch: pytest.MonkeyPatch):
    _patch_dns(monkeypatch, {"client.example": ["fe80::1"]})

    with pytest.raises(CimdResolverError, match="blocked IPs"):
        _validate_cimd_url("https://client.example/metadata.json", dev_mode=False)


def test_reject_metadata_service(monkeypatch: pytest.MonkeyPatch):
    _patch_dns(monkeypatch, {"metadata.example": ["169.254.169.254"]})

    with pytest.raises(CimdResolverError, match="169.254.169.254"):
        _validate_cimd_url("https://metadata.example/metadata.json", dev_mode=False)


def test_valid_cimd_url_passes(monkeypatch: pytest.MonkeyPatch):
    _patch_dns(monkeypatch, {"valid.example.com": ["203.0.113.10"]})

    validated = _validate_cimd_url("https://valid.example.com/metadata.json", dev_mode=False)

    assert validated == "https://valid.example.com/metadata.json"


def test_cache_hit_returns_cached(monkeypatch: pytest.MonkeyPatch):
    url = "https://valid.example.com/metadata.json"
    _patch_dns(monkeypatch, {"valid.example.com": ["203.0.113.10"]})
    call_count = {"count": 0}

    def handler(requested_url: str) -> httpx.Response:
        call_count["count"] += 1
        return _response(
            requested_url,
            json_body={
                "client_id": url,
                "client_name": "Cache Test Client",
                "redirect_uris": ["https://client.example/callback"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": "mcp:tools:list mcp:tools:echo",
            },
        )

    _patch_http_client(monkeypatch, handler)
    resolver = ClientMetadataResolver()

    first = resolver.resolve(url)
    second = resolver.resolve(url)

    assert first is not None
    assert second is not None
    assert first.client_id == second.client_id
    assert call_count["count"] == 1


def test_is_private_ip_helpers():
    assert _is_private_ip("10.0.0.1") is True
    assert _is_private_ip("172.16.5.4") is True
    assert _is_private_ip("192.168.1.8") is True
    assert _is_private_ip("127.0.0.1") is True
    assert _is_private_ip("169.254.169.254") is True
    assert _is_private_ip("::1") is True
    assert _is_private_ip("fd12::1") is True
    assert _is_private_ip("fe80::1") is True
    assert _is_private_ip("203.0.113.10") is False


def test_successful_metadata_fetch(monkeypatch: pytest.MonkeyPatch):
    url = "https://valid.example.com/metadata.json"
    _patch_dns(monkeypatch, {"valid.example.com": ["203.0.113.10"]})
    _patch_http_client(
        monkeypatch,
        lambda requested_url: _response(
            requested_url,
            json_body={
                "client_id": url,
                "client_name": "Resolved Client",
                "redirect_uris": ["https://client.example/callback"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": "mcp:tools:list mcp:tools:echo",
            },
        ),
    )

    resolver = ClientMetadataResolver()
    record = resolver.resolve(url)

    assert record is not None
    assert record.client_id == url
    assert record.redirect_uris == ("https://client.example/callback",)


def test_invalid_json_response(monkeypatch: pytest.MonkeyPatch):
    _patch_http_client(
        monkeypatch,
        lambda requested_url: _response(requested_url, content=b"this is not json"),
    )

    with pytest.raises(CimdFetchError, match="valid JSON"):
        _fetch_metadata("https://valid.example.com/metadata.json", timeout=1.0)


def test_client_id_mismatch(monkeypatch: pytest.MonkeyPatch):
    url = "https://valid.example.com/metadata.json"
    _patch_dns(monkeypatch, {"valid.example.com": ["203.0.113.10"]})
    _patch_http_client(
        monkeypatch,
        lambda requested_url: _response(
            requested_url,
            json_body={
                "client_id": "https://different.example.com/metadata.json",
                "redirect_uris": ["https://client.example/callback"],
            },
        ),
    )

    resolver = ClientMetadataResolver()

    assert resolver.resolve(url) is None
    assert trace_logger.get_events(event_type="cimd_validation_error", limit=1)


def test_missing_required_fields(monkeypatch: pytest.MonkeyPatch):
    url = "https://valid.example.com/metadata.json"
    _patch_dns(monkeypatch, {"valid.example.com": ["203.0.113.10"]})
    _patch_http_client(
        monkeypatch,
        lambda requested_url: _response(
            requested_url,
            json_body={"client_id": url},
        ),
    )

    resolver = ClientMetadataResolver()

    assert resolver.resolve(url) is None
    assert trace_logger.get_events(event_type="cimd_validation_error", limit=1)


def test_redirect_uri_mismatch(monkeypatch: pytest.MonkeyPatch):
    url = "https://valid.example.com/metadata.json"
    _patch_dns(monkeypatch, {"valid.example.com": ["203.0.113.10"]})
    _patch_http_client(
        monkeypatch,
        lambda requested_url: _response(
            requested_url,
            json_body={
                "client_id": url,
                "redirect_uris": ["https://client.example/callback"],
            },
        ),
    )

    resolver = ClientMetadataResolver()
    flow = CimdAuthFlow(resolver=resolver)
    record = flow.resolve_and_validate(url)

    assert record is not None
    assert flow.validate_redirect_uri(record, "https://client.example/other-callback") is False
    assert trace_logger.get_events(event_type="authorize_redirect_uri_mismatch", limit=1)


def test_oversized_response_rejected(monkeypatch: pytest.MonkeyPatch):
    oversized_body = b"x" * ((64 * 1024) + 1)
    _patch_http_client(
        monkeypatch,
        lambda requested_url: _response(requested_url, content=oversized_body),
    )

    with pytest.raises(CimdFetchError, match="64KB"):
        _fetch_metadata("https://valid.example.com/metadata.json", timeout=1.0)


def test_network_timeout(monkeypatch: pytest.MonkeyPatch):
    _patch_http_client(
        monkeypatch,
        lambda requested_url: httpx.TimeoutException(
            "timed out",
            request=httpx.Request("GET", requested_url),
        ),
    )

    with pytest.raises(CimdFetchError, match="timed out"):
        _fetch_metadata("https://valid.example.com/metadata.json", timeout=1.0)


def test_redirect_to_http_rejected(monkeypatch: pytest.MonkeyPatch):
    redirects = {
        "https://valid.example.com/metadata.json": _response(
            "https://valid.example.com/metadata.json",
            status_code=302,
            headers={"location": "http://evil.example.com/metadata.json"},
        )
    }
    _patch_http_client(monkeypatch, lambda requested_url: redirects[requested_url])

    with pytest.raises(CimdFetchError, match="must use https"):
        _fetch_metadata("https://valid.example.com/metadata.json", timeout=1.0)
