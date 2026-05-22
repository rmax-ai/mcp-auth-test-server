"""Tests for the no-auth MCP endpoint."""

import logging

import pytest


@pytest.mark.asyncio
async def test_initialize_returns_server_capabilities(client):
    response = await client.post(
        "/mcp/no-auth",
        json={"jsonrpc": "2.0", "id": "init-1", "method": "initialize", "params": {}},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["jsonrpc"] == "2.0"
    assert data["id"] == "init-1"
    assert data["result"]["protocolVersion"] == "2025-03-26"
    assert data["result"]["serverInfo"]["name"] == "mcp-auth-test-server"
    assert "tools" in data["result"]["capabilities"]


@pytest.mark.asyncio
async def test_tools_list_exposes_echo_and_ping(client):
    response = await client.post(
        "/mcp/no-auth",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )

    assert response.status_code == 200
    data = response.json()
    tools = {tool["name"]: tool for tool in data["result"]["tools"]}
    assert set(tools) == {"echo", "ping"}
    assert tools["echo"]["inputSchema"]["type"] == "object"
    assert "uppercase" in tools["echo"]["inputSchema"]["properties"]
    assert tools["echo"]["description"].startswith("Echo test tool")
    assert tools["ping"]["inputSchema"]["additionalProperties"] is False
    assert tools["ping"]["description"].startswith("Connectivity probe")


@pytest.mark.asyncio
async def test_echo_tool_returns_input_arguments(client):
    payload = {
        "jsonrpc": "2.0",
        "id": "echo-1",
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {"message": "hello", "count": 2},
        },
    }

    response = await client.post("/mcp/no-auth", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["result"]["structuredContent"] == {"message": "hello", "count": 2}
    assert data["result"]["isError"] is False


@pytest.mark.asyncio
async def test_echo_tool_uppercases_message_when_requested(client):
    payload = {
        "jsonrpc": "2.0",
        "id": "echo-uppercase-1",
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {"message": "hello", "uppercase": True},
        },
    }

    response = await client.post("/mcp/no-auth", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["result"]["structuredContent"] == {"message": "HELLO", "uppercase": True}


@pytest.mark.asyncio
async def test_ping_tool_returns_pong(client):
    response = await client.post(
        "/mcp/no-auth",
        json={
            "jsonrpc": "2.0",
            "id": "ping-1",
            "method": "tools/call",
            "params": {"name": "ping", "arguments": {}},
        },
    )

    assert response.status_code == 200
    assert response.json()["result"]["structuredContent"] == {"pong": True}


@pytest.mark.asyncio
async def test_tool_call_is_logged_with_request_context(client, caplog):
    caplog.set_level(logging.INFO, logger="mcp_auth_test_server.audit")

    response = await client.post(
        "/mcp/no-auth",
        json={
            "jsonrpc": "2.0",
            "id": "log-echo-1",
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": "hello", "count": 1}},
        },
    )

    assert response.status_code == 200
    assert any(
        "mcp request endpoint=/mcp/no-auth auth_scheme=none caller=anonymous" in record.message
        and "method=tools/call" in record.message
        and "tool_name=echo" in record.message
        and "argument_keys=['count', 'message']" in record.message
        for record in caplog.records
    )


@pytest.mark.asyncio
async def test_unknown_method_returns_json_rpc_error(client):
    response = await client.post(
        "/mcp/no-auth",
        json={"jsonrpc": "2.0", "id": "bad-1", "method": "missing", "params": {}},
    )

    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] == -32601
    assert data["error"]["message"] == "Method not found"


@pytest.mark.asyncio
async def test_initialized_notification_is_accepted(client):
    response = await client.post(
        "/mcp/no-auth",
        json={
            "jsonrpc": "2.0",
            "id": None,
            "method": "notifications/initialized",
            "params": {},
        },
    )

    assert response.status_code == 204


@pytest.mark.asyncio
async def test_ping_request_returns_empty_result(client):
    response = await client.post(
        "/mcp/no-auth",
        json={"jsonrpc": "2.0", "id": "ping-rpc", "method": "ping", "params": {}},
    )

    assert response.status_code == 200
    assert response.json()["result"] == {}


@pytest.mark.asyncio
async def test_invalid_request_returns_json_rpc_error(client):
    response = await client.post(
        "/mcp/no-auth",
        json={"jsonrpc": "1.0", "id": "bad-2", "method": "tools/list", "params": {}},
    )

    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] == -32600
    assert data["id"] == "bad-2"
