"""Core MCP tool definitions used across endpoints."""

from __future__ import annotations

from typing import Any

from mcp_auth_test_server.mcp.base import ToolDefinition


async def echo_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Return caller-provided arguments, with optional message uppercasing."""

    result = dict(arguments)
    if result.get("uppercase") and isinstance(result.get("message"), str):
        result["message"] = result["message"].upper()
    return result


async def ping_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Basic health-style tool for connectivity checks."""

    _ = arguments
    return {"pong": True}


def get_core_tools() -> list[ToolDefinition]:
    """Return the baseline MCP tool set exposed by test endpoints."""

    return [
        ToolDefinition(
            name="echo",
            description=(
                "Echo test tool that returns caller arguments and can optionally "
                "uppercase the `message` field."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Message to echo back in the response.",
                    },
                    "count": {
                        "type": "integer",
                        "description": "Optional counter value echoed back as-is.",
                    },
                    "uppercase": {
                        "type": "boolean",
                        "description": "When true, `message` is returned in uppercase.",
                        "default": False,
                    },
                },
                "required": ["message"],
                "additionalProperties": False,
            },
            handler=echo_tool,
        ),
        ToolDefinition(
            name="ping",
            description='Connectivity probe that always returns `{ "pong": true }`.',
            input_schema={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            handler=ping_tool,
        ),
    ]
