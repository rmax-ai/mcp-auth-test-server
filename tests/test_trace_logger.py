"""Tests for the in-memory OAuth trace logger."""

from __future__ import annotations

from mcp_auth_test_server.auth.trace_logger import OAuthTraceEvent, OAuthTraceLogger


def test_record_and_retrieve():
    logger = OAuthTraceLogger()
    logger.record(
        OAuthTraceEvent(
            event_type="cimd_fetch_success",
            client_id="client-1",
            detail="resolved",
            result="success",
        )
    )
    logger.record(
        OAuthTraceEvent(
            event_type="dcr_register_success",
            client_id="client-2",
            detail="registered",
            result="success",
        )
    )

    events = logger.get_events(event_type="cimd_fetch_success")

    assert len(events) == 1
    assert events[0].client_id == "client-1"


def test_max_events():
    logger = OAuthTraceLogger(max_events=2)
    logger.record(OAuthTraceEvent(event_type="one", client_id=None, detail="1", result="success"))
    logger.record(OAuthTraceEvent(event_type="two", client_id=None, detail="2", result="success"))
    logger.record(OAuthTraceEvent(event_type="three", client_id=None, detail="3", result="success"))

    events = logger.get_events(limit=10)

    assert [event.event_type for event in events] == ["three", "two"]


def test_clear():
    logger = OAuthTraceLogger()
    logger.record(OAuthTraceEvent(event_type="one", client_id=None, detail="1", result="success"))

    logger.clear()

    assert logger.get_events(limit=10) == []


def test_event_as_dict():
    event = OAuthTraceEvent(
        event_type="token_exchange_success",
        client_id="client-1",
        detail="token issued",
        result="success",
        metadata={"grant_type": "authorization_code"},
    )

    payload = event.as_debug_dict()

    assert payload["event_type"] == "token_exchange_success"
    assert payload["client_id"] == "client-1"
    assert payload["metadata"] == {"grant_type": "authorization_code"}
    assert payload["timestamp"].endswith("+00:00")
