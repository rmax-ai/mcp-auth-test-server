"""Core MCP tool definitions used across endpoints."""

from __future__ import annotations

from typing import Any

from mcp_auth_test_server.mcp.base import ToolDefinition


async def echo_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Return the exact arguments provided by the caller."""

    return arguments


async def ping_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Basic health-style tool for connectivity checks."""

    _ = arguments
    return {"pong": True}


def get_core_tools() -> list[ToolDefinition]:
    """Return the baseline MCP tool set exposed by test endpoints."""

    return [
        ToolDefinition(
            name="echo",
            description="Return the provided arguments unchanged.",
            input_schema={
                "type": "object",
                "additionalProperties": True,
            },
            handler=echo_tool,
        ),
        ToolDefinition(
            name="ping",
            description='Return {"pong": true}.',
            input_schema={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            handler=ping_tool,
        ),
    ]
