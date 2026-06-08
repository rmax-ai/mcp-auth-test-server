"""Structured trace logging for OAuth, DCR, and CIMD flows."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock


@dataclass(slots=True)
class OAuthTraceEvent:
    """A structured trace event safe for debug inspection."""

    event_type: str
    client_id: str | None
    detail: str
    result: str
    metadata: dict[str, object] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def as_debug_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""

        return {
            "event_type": self.event_type,
            "client_id": self.client_id,
            "detail": self.detail,
            "result": self.result,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
        }


class OAuthTraceLogger:
    """In-memory trace event recorder with bounded retention."""

    def __init__(self, max_events: int = 1000) -> None:
        self._events: deque[OAuthTraceEvent] = deque(maxlen=max_events)
        self._lock = Lock()

    def record(self, event: OAuthTraceEvent) -> None:
        """Append a trace event."""

        with self._lock:
            self._events.append(event)

    def clear(self) -> None:
        """Remove all trace events."""

        with self._lock:
            self._events.clear()

    def get_events(
        self,
        event_type: str | None = None,
        limit: int = 50,
    ) -> list[OAuthTraceEvent]:
        """Return recent events, optionally filtered by type."""

        capped_limit = max(limit, 0)
        with self._lock:
            events = list(self._events)
        if event_type is not None:
            events = [event for event in events if event.event_type == event_type]
        if capped_limit == 0:
            return []
        return list(reversed(events[-capped_limit:]))


trace_logger = OAuthTraceLogger()
