"""Test-control endpoints for fault injection, time control, and state inspection."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from mcp_auth_test_server.auth.audit import AuditEvent, redact
from mcp_auth_test_server.auth.bearer import reset_minted_tokens
from mcp_auth_test_server.discovery import MOCK_SCOPES

router = APIRouter()

_FAULTS: dict[str, dict[str, Any]] = {}
_CLOCK: dict[str, datetime | int | None] = {
    "freeze_at": None,
    "offset_seconds": 0,
}
_SCOPE_OVERRIDE: dict[str, list[str] | None] = {"scopes": None}
_POLICY_FLAGS: dict[str, bool] = {"scope_enforcement_enabled": True}


class FaultInjectionRequest(BaseModel):
    """Request model for one-shot fault injection."""

    endpoint: str
    behavior: Literal["delay", "error", "timeout", "reject"]
    params: dict[str, Any] = Field(default_factory=dict)


class ExpiredTokenRequest(BaseModel):
    """Request model for minting an already-expired OAuth bearer token."""

    subject: str = "test-user"
    scope: str = "mcp:tools:read"
    audience: str = "http://127.0.0.1:8765/mcp/oauth"


class ScopeOverrideRequest(BaseModel):
    """Request model for supported-scope overrides."""

    scopes: list[str]


class ClockControlRequest(BaseModel):
    """Request model for mutating the effective server clock."""

    advance_seconds: int | None = None
    freeze_at: datetime | None = None


class PolicyConfigRequest(BaseModel):
    """Request model for scope-policy enforcement toggles."""

    scope_enforcement_enabled: bool


def get_current_time() -> datetime:
    """Return the effective server time after test clock overrides."""

    frozen_at = _CLOCK["freeze_at"]
    if isinstance(frozen_at, datetime):
        return frozen_at

    offset_seconds = _CLOCK["offset_seconds"]
    if not isinstance(offset_seconds, int):
        offset_seconds = 0
    return datetime.now(tz=UTC) + timedelta(seconds=offset_seconds)


def get_supported_scopes() -> list[str]:
    """Return the active supported-scope set for auth and discovery."""

    override = _SCOPE_OVERRIDE["scopes"]
    if override is None:
        return list(MOCK_SCOPES)
    return list(override)


def is_scope_enforcement_enabled() -> bool:
    """Return True when MCP scope checks should be enforced."""

    return _POLICY_FLAGS["scope_enforcement_enabled"]


async def maybe_apply_fault(request: Request) -> Response | None:
    """Apply a configured one-shot fault before the target handler runs."""

    endpoint = _normalize_endpoint(request.url.path)
    fault = _FAULTS.pop(endpoint, None)
    if fault is None:
        return None

    behavior = fault["behavior"]
    params = fault["params"]
    _record_test_event(
        event_type="test_fault_triggered",
        result=behavior,
        detail=f"endpoint={endpoint} params={params}",
    )

    if behavior == "delay":
        await asyncio.sleep(_float_param(params, "delay_seconds", default=1.0))
        return None

    if behavior == "timeout":
        timeout_seconds = _float_param(
            params,
            "timeout_seconds",
            fallback_key="delay_seconds",
            default=30.0,
        )
        await asyncio.sleep(timeout_seconds)
        return JSONResponse(
            status_code=_int_param(params, "status_code", default=504),
            content={
                "detail": params.get("message", "Injected timeout"),
                "behavior": behavior,
                "endpoint": endpoint,
            },
        )

    if behavior == "reject":
        return JSONResponse(
            status_code=_int_param(params, "status_code", default=403),
            content={
                "detail": params.get("message", "Injected rejection"),
                "behavior": behavior,
                "endpoint": endpoint,
            },
        )

    return JSONResponse(
        status_code=_int_param(params, "status_code", default=500),
        content={
            "detail": params.get("message", "Injected fault"),
            "behavior": behavior,
            "endpoint": endpoint,
        },
    )


@router.post("/faults")
async def configure_fault(body: FaultInjectionRequest) -> dict[str, object]:
    """Configure a one-shot fault for an exact request path."""

    endpoint = _normalize_endpoint(body.endpoint)
    _FAULTS[endpoint] = {
        "behavior": body.behavior,
        "params": dict(body.params),
        "configured_at": get_current_time(),
    }
    _record_test_event(
        event_type="test_fault_configured",
        result=body.behavior,
        detail=f"endpoint={endpoint} params={body.params}",
    )
    return {
        "endpoint": endpoint,
        "behavior": body.behavior,
        "params": body.params,
        "one_shot": True,
    }


@router.post("/tokens/expired")
async def mint_expired_token(body: ExpiredTokenRequest) -> dict[str, object]:
    """Mint and persist an already-expired OAuth bearer token."""

    from mcp_auth_test_server.auth.token_store import AccessTokenRecord

    token = f"expired_{redact(f'{body.subject}:{body.scope}:{body.audience}:{get_current_time()}')}"
    expires_at = get_current_time() - timedelta(seconds=1)
    record = AccessTokenRecord(
        access_token=token,
        client_id=body.subject,
        scope=body.scope,
        grant_type="test_expired",
        audience=body.audience,
        issuer="test-endpoint",
        expires_at=expires_at,
    )
    oauth_token_store = _get_oauth_token_store()
    oauth_token_store._access_tokens[token] = record  # noqa: SLF001
    oauth_token_store._audit_events.append(  # noqa: SLF001
        AuditEvent(
            event_type="token_issued",
            client_id=body.subject,
            scope=body.scope,
            grant_type=record.grant_type,
            result="issued_expired",
            detail=f"audience={body.audience}",
            token_hash=redact(token),
        )
    )
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 0,
    }


@router.post("/configure/scopes")
async def configure_scopes(body: ScopeOverrideRequest) -> dict[str, object]:
    """Override the advertised and accepted OAuth scope set."""

    if not body.scopes:
        raise HTTPException(status_code=400, detail="scopes must not be empty")

    _SCOPE_OVERRIDE["scopes"] = list(body.scopes)
    _record_test_event(
        event_type="test_scope_override",
        result="configured",
        detail=f"scopes={body.scopes}",
    )
    return {"scopes": list(body.scopes)}


@router.post("/reset")
async def reset_state() -> dict[str, object]:
    """Reset in-memory auth state and all test-control overrides."""

    oauth_token_store = _get_oauth_token_store()
    oauth_token_store.reset()
    reset_minted_tokens()
    _FAULTS.clear()
    _CLOCK["freeze_at"] = None
    _CLOCK["offset_seconds"] = 0
    _SCOPE_OVERRIDE["scopes"] = None
    _POLICY_FLAGS["scope_enforcement_enabled"] = True
    _record_test_event(
        event_type="test_reset",
        result="reset",
        detail="reset oauth state and test controls",
    )
    return {"reset": True}


@router.get("/state")
async def get_state() -> dict[str, object]:
    """Return a test-oriented snapshot of in-memory auth and control state."""

    oauth_token_store = _get_oauth_token_store()
    return {
        "authorization_codes": [
            {
                "code": code,
                "code_hash": redact(code),
                "client_id": record.client_id,
                "redirect_uri": record.redirect_uri,
                "scope": record.scope,
                "resource": record.resource,
                "code_challenge": record.code_challenge,
                "code_challenge_method": record.code_challenge_method,
                "expires_at": record.expires_at.isoformat(),
            }
            for code, record in oauth_token_store._authorization_codes.items()  # noqa: SLF001
        ],
        "access_tokens": [
            {
                "access_token": token,
                "token_hash": redact(token),
                "client_id": record.client_id,
                "scope": record.scope,
                "grant_type": record.grant_type,
                "audience": record.audience,
                "issuer": record.issuer,
                "expires_at": record.expires_at.isoformat(),
                "token_type": record.token_type,
            }
            for token, record in oauth_token_store._access_tokens.items()  # noqa: SLF001
        ],
        "refresh_tokens": [
            {
                "refresh_token": token,
                "client_id": record.client_id,
                "scope": record.scope,
                "grant_type": record.grant_type,
                "audience": record.audience,
                "issuer": record.issuer,
                "expires_at": record.expires_at.isoformat(),
            }
            for token, record in oauth_token_store._refresh_tokens.items()  # noqa: SLF001
        ],
        "device_codes": [
            {
                "device_code": record.device_code,
                "user_code": record.user_code,
                "client_id": record.client_id,
                "scope": record.scope,
                "verified": record.verified,
                "expires_at": (
                    record.expires_at.isoformat() if record.expires_at is not None else None
                ),
            }
            for record in oauth_token_store._device_codes.values()  # noqa: SLF001
        ],
        "clients": [
            {
                "client_id": client_id,
                "client_secret": record.client_secret,
                "token_endpoint_auth_method": record.token_endpoint_auth_method,
                "grant_types": list(record.grant_types),
                "response_types": list(record.response_types),
                "redirect_uris": list(record.redirect_uris),
                "scope": record.scope,
                "client_name": record.client_name,
                "client_id_issued_at": record.client_id_issued_at,
                "client_secret_expires_at": record.client_secret_expires_at,
            }
            for client_id, record in oauth_token_store._clients.items()  # noqa: SLF001
        ],
        "approvals": [
            {
                "client_id": record.client_id,
                "scope": record.scope,
                "decision": record.decision,
                "mode": record.mode.value,
                "timestamp": record.timestamp.isoformat(),
                "admin_scope_confirmed": record.admin_scope_confirmed,
            }
            for record in oauth_token_store.get_approval_records()
        ],
        "faults": {
            endpoint: {
                "behavior": fault["behavior"],
                "params": fault["params"],
                "configured_at": fault["configured_at"].isoformat(),
            }
            for endpoint, fault in _FAULTS.items()
        },
        "clock": {
            "freeze_at": (
                _CLOCK["freeze_at"].isoformat()
                if isinstance(_CLOCK["freeze_at"], datetime)
                else None
            ),
            "offset_seconds": _CLOCK["offset_seconds"],
            "now": get_current_time().isoformat(),
        },
        "scope_override": {
            "scopes": get_supported_scopes(),
            "is_overridden": _SCOPE_OVERRIDE["scopes"] is not None,
        },
        "policy": {
            "scope_enforcement_enabled": _POLICY_FLAGS["scope_enforcement_enabled"],
        },
    }


@router.get("/cimd/{fixture}.json")
async def get_cimd_fixture(fixture: str, request: Request) -> JSONResponse:
    """Serve deterministic CIMD fixture documents for resolver testing."""

    document_url = str(request.url)
    if fixture == "slow":
        await asyncio.sleep(5)
        return JSONResponse(_build_valid_cimd_document(document_url))
    if fixture == "valid":
        return JSONResponse(_build_valid_cimd_document(document_url))
    if fixture == "mismatched":
        document = _build_valid_cimd_document(document_url)
        document["client_id"] = document_url.replace("mismatched.json", "valid.json")
        return JSONResponse(document)
    if fixture == "malformed":
        return JSONResponse(
            {
                "client_id": document_url,
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "scope": "mcp:tools:list",
            }
        )
    raise HTTPException(status_code=404, detail=f"unknown CIMD fixture: {fixture}")


@router.post("/clock")
async def configure_clock(body: ClockControlRequest) -> dict[str, object]:
    """Advance the effective server time or freeze it at an explicit instant."""

    if (body.advance_seconds is None) == (body.freeze_at is None):
        raise HTTPException(
            status_code=400,
            detail="provide exactly one of advance_seconds or freeze_at",
        )

    if body.freeze_at is not None:
        if body.freeze_at.tzinfo is None:
            raise HTTPException(status_code=400, detail="freeze_at must include a timezone")
        _CLOCK["freeze_at"] = body.freeze_at.astimezone(UTC)
        _CLOCK["offset_seconds"] = 0
        _record_test_event(
            event_type="test_clock_configured",
            result="frozen",
            detail=f"freeze_at={_CLOCK['freeze_at'].isoformat()}",
        )
    else:
        assert body.advance_seconds is not None
        frozen_at = _CLOCK["freeze_at"]
        if isinstance(frozen_at, datetime):
            _CLOCK["freeze_at"] = frozen_at + timedelta(seconds=body.advance_seconds)
        else:
            offset_seconds = _CLOCK["offset_seconds"]
            assert isinstance(offset_seconds, int)
            _CLOCK["offset_seconds"] = offset_seconds + body.advance_seconds
        _record_test_event(
            event_type="test_clock_configured",
            result="advanced",
            detail=f"advance_seconds={body.advance_seconds}",
        )

    return {
        "freeze_at": (
            _CLOCK["freeze_at"].isoformat() if isinstance(_CLOCK["freeze_at"], datetime) else None
        ),
        "offset_seconds": _CLOCK["offset_seconds"],
        "now": get_current_time().isoformat(),
    }


@router.post("/configure/policy")
async def configure_policy(body: PolicyConfigRequest) -> dict[str, object]:
    """Enable or disable mounted-route scope enforcement."""

    _POLICY_FLAGS["scope_enforcement_enabled"] = body.scope_enforcement_enabled
    _record_test_event(
        event_type="test_policy_configured",
        result="enabled" if body.scope_enforcement_enabled else "disabled",
        detail=f"scope_enforcement_enabled={body.scope_enforcement_enabled}",
    )
    return {
        "scope_enforcement_enabled": body.scope_enforcement_enabled,
    }


def _normalize_endpoint(endpoint: str) -> str:
    endpoint = endpoint.strip() or "/"
    if not endpoint.startswith("/"):
        endpoint = f"/{endpoint}"
    if endpoint != "/":
        endpoint = endpoint.rstrip("/")
    return endpoint


def _record_test_event(*, event_type: str, result: str, detail: str) -> None:
    oauth_token_store = _get_oauth_token_store()
    oauth_token_store._audit_events.append(  # noqa: SLF001
        AuditEvent(
            event_type=event_type,
            client_id="test-endpoints",
            result=result,
            detail=detail,
        )
    )


def _float_param(
    params: dict[str, Any],
    key: str,
    *,
    fallback_key: str | None = None,
    default: float,
) -> float:
    value = params.get(key, params.get(fallback_key) if fallback_key is not None else default)
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int_param(params: dict[str, Any], key: str, *, default: int) -> int:
    value = params.get(key, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _build_valid_cimd_document(document_url: str) -> dict[str, object]:
    return {
        "client_id": document_url,
        "redirect_uris": ["http://localhost:3000/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "mcp:tools:list mcp:tools:read",
        "client_name": "Valid CIMD Fixture",
    }


def _get_oauth_token_store():
    from mcp_auth_test_server.auth.token_store import oauth_token_store

    return oauth_token_store
