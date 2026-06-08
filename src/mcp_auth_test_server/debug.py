"""Debug endpoints for inspecting in-memory OAuth and audit state."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from mcp_auth_test_server.auth.token_store import oauth_token_store
from mcp_auth_test_server.auth.trace_logger import trace_logger

router = APIRouter()


@router.get("/debug/authorizations")
async def debug_authorizations() -> JSONResponse:
    """Return all issued authorization codes (redacted hashes only)."""
    codes = []
    for code, record in oauth_token_store._authorization_codes.items():  # noqa: SLF001
        from mcp_auth_test_server.auth.audit import redact

        codes.append(
            {
                "code_hash": redact(code),
                "client_id": record.client_id,
                "scope": record.scope,
                "resource": record.resource,
                "expires_at": record.expires_at.isoformat(),
            }
        )
    return JSONResponse({"authorizations": codes})


@router.get("/debug/approvals")
async def debug_approvals() -> JSONResponse:
    """Return all recorded approval decisions."""
    records = [
        {
            "client_id": r.client_id,
            "scope": r.scope,
            "decision": r.decision,
            "mode": r.mode.value,
            "admin_scope_confirmed": r.admin_scope_confirmed,
            "timestamp": r.timestamp.isoformat(),
        }
        for r in oauth_token_store.get_approval_records()
    ]
    return JSONResponse({"approvals": records})


@router.get("/debug/tokens")
async def debug_tokens() -> JSONResponse:
    """Return all issued access tokens (redacted hashes only)."""
    tokens = []
    for token, record in oauth_token_store._access_tokens.items():  # noqa: SLF001
        from mcp_auth_test_server.auth.audit import redact

        tokens.append(
            {
                "token_hash": redact(token),
                "client_id": record.client_id,
                "scope": record.scope,
                "grant_type": record.grant_type,
                "audience": record.audience,
                "issuer": record.issuer,
                "expires_at": record.expires_at.isoformat(),
            }
        )
    return JSONResponse({"tokens": tokens})


@router.get("/debug/clients")
async def debug_clients() -> JSONResponse:
    """Return all registered clients (secrets redacted)."""
    clients = []
    for client_id, record in oauth_token_store._clients.items():  # noqa: SLF001
        entry: dict[str, object] = {
            "client_id": client_id,
            "token_endpoint_auth_method": record.token_endpoint_auth_method,
            "grant_types": list(record.grant_types),
            "response_types": list(record.response_types),
            "scope": record.scope,
            "client_name": record.client_name,
            "client_id_issued_at": record.client_id_issued_at,
            "has_client_secret": record.client_secret is not None,
        }
        if record.redirect_uris:
            entry["redirect_uris"] = list(record.redirect_uris)
        clients.append(entry)
    return JSONResponse({"clients": clients})


@router.get("/debug/audit")
async def debug_audit() -> JSONResponse:
    """Return all recorded audit events."""
    events = [event.as_debug_dict() for event in oauth_token_store.get_audit_events()]
    return JSONResponse({"audit_events": events})


@router.get("/debug/traces")
async def debug_traces(event_type: str | None = None, limit: int = 50) -> JSONResponse:
    """Return structured OAuth trace events from the trace logger."""
    events = trace_logger.get_events(event_type=event_type, limit=limit)
    return JSONResponse({"trace_events": [event.as_debug_dict() for event in events]})
