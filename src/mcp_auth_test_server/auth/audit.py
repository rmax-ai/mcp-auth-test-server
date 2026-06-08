"""Audit event recording for mock OAuth activity."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime


def redact(value: str) -> str:
    """Return a truncated SHA-256 prefix for debug display."""
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _audit_now() -> datetime:
    try:
        from mcp_auth_test_server.test_endpoints import get_current_time
    except ImportError:
        return datetime.now(tz=UTC)
    return get_current_time()


@dataclass(slots=True)
class AuditEvent:
    """A structured audit record for a single OAuth or MCP operation."""

    event_type: str
    """One of: token_issued, authorization_code_issued, approval, registration,
    mcp_request, policy_denied."""

    client_id: str | None = None
    scope: str | None = None
    grant_type: str | None = None
    tool: str | None = None
    result: str | None = None
    detail: str | None = None

    token_hash: str | None = None
    """SHA-256 prefix of the access token (never the full token)."""

    code_hash: str | None = None
    """SHA-256 prefix of the authorization code (never the full code)."""

    timestamp: datetime = field(default_factory=_audit_now)

    def as_debug_dict(self) -> dict[str, object]:
        """Return a dict safe for debug endpoint exposure."""
        return {
            "event_type": self.event_type,
            "client_id": self.client_id,
            "scope": self.scope,
            "grant_type": self.grant_type,
            "tool": self.tool,
            "result": self.result,
            "detail": self.detail,
            "token_hash": self.token_hash,
            "code_hash": self.code_hash,
            "timestamp": self.timestamp.isoformat(),
        }
