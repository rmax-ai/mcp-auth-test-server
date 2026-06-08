"""Tests for debug and audit endpoints."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from mcp_auth_test_server.auth.trace_logger import OAuthTraceEvent, trace_logger
from tests.flow_helpers import code_challenge

MOCK_OAUTH_RESOURCE = "http://test/mcp/oauth"


@pytest.mark.asyncio
async def test_debug_endpoints_available(client):
    """All debug endpoints return 200 when called."""
    for path in (
        "/debug/audit",
        "/debug/approvals",
        "/debug/tokens",
        "/debug/authorizations",
        "/debug/clients",
        "/debug/traces",
    ):
        response = await client.get(path)
        assert response.status_code == 200, f"{path} returned {response.status_code}"


@pytest.mark.asyncio
async def test_debug_traces_filters_by_event_type(client):
    """Trace debug endpoint returns structured trace events and supports filtering."""
    trace_logger.clear()
    trace_logger.record(
        OAuthTraceEvent(
            event_type="cimd_fetch_success",
            client_id="https://client.example/metadata.json",
            detail="resolved",
            result="success",
        )
    )
    trace_logger.record(
        OAuthTraceEvent(
            event_type="dcr_register_success",
            client_id="registered-client",
            detail="registered",
            result="success",
        )
    )

    response = await client.get("/debug/traces", params={"event_type": "cimd_fetch_success"})

    assert response.status_code == 200
    assert response.json()["trace_events"][0]["event_type"] == "cimd_fetch_success"


@pytest.mark.asyncio
async def test_debug_audit_records_token_issuance(client):
    """Running a full auth-code flow produces audit events for approval + code + token."""
    register = await client.post(
        "/oauth/register",
        json={
            "client_name": "Audit Test Client",
            "redirect_uris": ["https://client.example/audit/callback"],
            "scope": "mcp:tools:list mcp:tools:echo mcp:tools:read",
        },
    )
    registration = register.json()
    verifier = "audit-test-verifier"

    await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": "https://client.example/audit/callback",
            "scope": "mcp:tools:list mcp:tools:echo mcp:tools:read",
            "state": "audit-state",
            "resource": MOCK_OAUTH_RESOURCE,
            "code_challenge": code_challenge(verifier),
            "code_challenge_method": "S256",
            "auto_approve": "true",
        },
        follow_redirects=False,
    )

    audit = await client.get("/debug/audit")
    events = audit.json()["audit_events"]
    event_types = {e["event_type"] for e in events}

    assert "registration" in event_types
    assert "authorization_code_issued" in event_types
    assert "approval" in event_types


@pytest.mark.asyncio
async def test_debug_tokens_no_raw_token_leakage(client):
    """Debug token endpoint returns hashes, not raw tokens."""
    register = await client.post(
        "/oauth/register",
        json={
            "client_name": "Leak Test Client",
            "redirect_uris": ["https://client.example/leak/callback"],
            "scope": "mcp:tools:list",
        },
    )
    registration = register.json()
    verifier = "leak-test-verifier"

    authorize = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": "https://client.example/leak/callback",
            "scope": "mcp:tools:list",
            "state": "leak-state",
            "resource": MOCK_OAUTH_RESOURCE,
            "code_challenge": code_challenge(verifier),
            "code_challenge_method": "S256",
            "auto_approve": "true",
        },
        follow_redirects=False,
    )

    location = authorize.headers["location"]
    auth_code = parse_qs(urlparse(location).query)["code"][0]

    token = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": "https://client.example/leak/callback",
            "client_id": registration["client_id"],
            "code_verifier": verifier,
            "resource": MOCK_OAUTH_RESOURCE,
        },
    )
    raw_token = token.json()["access_token"]

    debug_tokens = await client.get("/debug/tokens")
    token_entries = debug_tokens.json()["tokens"]
    for entry in token_entries:
        token_hash = entry["token_hash"]
        assert len(token_hash) >= 10  # redacted but not empty
        assert token_hash not in raw_token  # hash should not match raw token


@pytest.mark.asyncio
async def test_debug_approvals_records_allow_and_deny(client):
    """Both allow and deny paths produce approval records."""
    register = await client.post(
        "/oauth/register",
        json={
            "client_name": "Approval Test Client",
            "redirect_uris": ["https://client.example/approval/callback"],
            "scope": "mcp:tools:list",
        },
    )
    registration = register.json()
    verifier = "approval-test-verifier"
    ch = code_challenge(verifier)

    # Deny via auto_deny
    await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": "https://client.example/approval/callback",
            "scope": "mcp:tools:list",
            "state": "deny-state",
            "resource": MOCK_OAUTH_RESOURCE,
            "code_challenge": ch,
            "code_challenge_method": "S256",
            "approval_mode": "auto_deny",
        },
        follow_redirects=False,
    )

    debug = await client.get("/debug/approvals")
    records = debug.json()["approvals"]
    decisions = {r["decision"] for r in records}

    assert "denied" in decisions

    # Approve via auto_approve
    await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": registration["client_id"],
            "redirect_uri": "https://client.example/approval/callback",
            "scope": "mcp:tools:list",
            "state": "approve-state",
            "resource": MOCK_OAUTH_RESOURCE,
            "code_challenge": ch,
            "code_challenge_method": "S256",
            "auto_approve": "true",
        },
        follow_redirects=False,
    )

    debug = await client.get("/debug/approvals")
    records = debug.json()["approvals"]
    decisions = {r["decision"] for r in records}

    assert "approved" in decisions
    assert "denied" in decisions


@pytest.mark.asyncio
async def test_debug_clients_redacts_secrets(client):
    """Client debug endpoint does not expose raw secrets."""
    await client.post(
        "/oauth/register",
        json={
            "client_name": "Secret Test Client",
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
            "scope": "mcp:tools:write",
        },
    )

    debug = await client.get("/debug/clients")
    clients = debug.json()["clients"]
    for entry in clients:
        assert "client_secret" not in entry
        assert entry.get("has_client_secret") is True or entry.get("has_client_secret") is False
