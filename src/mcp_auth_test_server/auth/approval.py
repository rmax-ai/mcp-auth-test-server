"""Approval model for mock OAuth consent decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


def _approval_now() -> datetime:
    try:
        from mcp_auth_test_server.test_endpoints import get_current_time
    except ImportError:
        return datetime.now(tz=UTC)
    return get_current_time()


class ApprovalMode(StrEnum):
    """Controls how the mock authorization server handles consent."""

    MANUAL = "manual"
    AUTO_APPROVE = "auto_approve"
    AUTO_DENY = "auto_deny"


@dataclass(slots=True)
class ApprovalRecord:
    """A single recorded consent decision for audit / debug."""

    client_id: str
    scope: str
    decision: str  # "approved" | "denied"
    mode: ApprovalMode
    timestamp: datetime = field(default_factory=_approval_now)
    admin_scope_confirmed: bool = False


ADMIN_SCOPES = {"mcp:tools:admin"}


def has_admin_scope(scope: str) -> bool:
    """Return True when the scope string includes any admin-level scope."""
    return bool(set(scope.split()) & ADMIN_SCOPES)


def resolve_approval_mode(
    query_params: dict[str, str],
) -> ApprovalMode:
    """Determine the approval mode from request query parameters.

    Falls back to MANUAL when no explicit mode is given.
    """
    raw = query_params.get("approval_mode") or query_params.get("auto_approve")
    if raw == "true" or raw == ApprovalMode.AUTO_APPROVE.value:
        return ApprovalMode.AUTO_APPROVE
    if raw == ApprovalMode.AUTO_DENY.value:
        return ApprovalMode.AUTO_DENY
    return ApprovalMode.MANUAL
