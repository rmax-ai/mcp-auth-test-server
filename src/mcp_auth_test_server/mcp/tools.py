"""Core MCP tool definitions used across endpoints."""

from __future__ import annotations

from typing import Any

from mcp_auth_test_server.mcp.base import (
    ArgumentConstraint,
    ToolArgumentPolicy,
    ToolDefinition,
)

# ── Tool-to-Scope Mapping ────────────────────────────────────────────────────

TOOL_SCOPE_MAP: dict[str, str] = {
    "tools/list": "mcp:tools:list",
    "echo": "mcp:tools:echo",
    "ping": "mcp:tools:echo",
    "whoami": "mcp:tools:read",
    "read_note": "mcp:tools:read",
    "write_note": "mcp:tools:write",
    "dangerous_delete": "mcp:tools:admin",
}

# ── Argument Policy Definitions ──────────────────────────────────────────────

TOOL_ARGUMENT_POLICIES: dict[str, ToolArgumentPolicy] = {
    "write_note": ToolArgumentPolicy(
        required_params=["content"],
        constraints=[
            ArgumentConstraint(param="content", constraint_type="max_length", value=1000),
        ],
        blocked_patterns=["rm -rf", "DROP TABLE", "<script>"],
    ),
    "dangerous_delete": ToolArgumentPolicy(
        required_params=["confirm"],
        constraints=[
            ArgumentConstraint(param="confirm", constraint_type="equals", value=True),
        ],
        blocked_patterns=[],
        environment_flag="MCP_ALLOW_DANGEROUS",
    ),
}

# ── Tool Handlers ────────────────────────────────────────────────────────────

_NOTE_STORAGE: dict[str, str] = {}


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


async def whoami_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Return the authenticated client identity."""
    client_id = arguments.get("client_id", "anonymous")
    return {
        "identity": client_id,
        "authenticated": client_id != "anonymous",
    }


async def read_note_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Read a stored note by key."""
    key = arguments.get("key", "")
    if not key:
        return {"error": "key is required"}
    content = _NOTE_STORAGE.get(key)
    if content is None:
        return {"error": f"note not found: {key}"}
    return {"key": key, "content": content}


async def write_note_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Write a note under a given key."""
    key = arguments.get("key", "")
    content = arguments.get("content", "")
    if not key:
        return {"error": "key is required"}
    _NOTE_STORAGE[key] = content
    return {"key": key, "stored": True, "length": len(content)}


async def dangerous_delete_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    """Dangerous tool that requires explicit confirmation and env flag."""
    _ = arguments
    return {
        "action": "dangerous_delete",
        "status": "would_execute",
        "note": "Policy enforcement happens in Phase 2",
    }


# ── Tool Factory ─────────────────────────────────────────────────────────────


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
            required_scope=TOOL_SCOPE_MAP["echo"],
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
            required_scope=TOOL_SCOPE_MAP["ping"],
        ),
        ToolDefinition(
            name="whoami",
            description="Return the authenticated client identity.",
            input_schema={
                "type": "object",
                "properties": {
                    "client_id": {
                        "type": "string",
                        "description": "Optional client identifier",
                    },
                },
                "additionalProperties": False,
            },
            handler=whoami_tool,
            required_scope=TOOL_SCOPE_MAP["whoami"],
        ),
        ToolDefinition(
            name="read_note",
            description="Read a stored note by key.",
            input_schema={
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "Note key to retrieve",
                    },
                },
                "required": ["key"],
                "additionalProperties": False,
            },
            handler=read_note_tool,
            required_scope=TOOL_SCOPE_MAP["read_note"],
        ),
        ToolDefinition(
            name="write_note",
            description="Write a note under a given key.",
            input_schema={
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "Note key",
                    },
                    "content": {
                        "type": "string",
                        "description": "Note content to store",
                    },
                },
                "required": ["key", "content"],
                "additionalProperties": False,
            },
            handler=write_note_tool,
            required_scope=TOOL_SCOPE_MAP["write_note"],
            argument_policy=TOOL_ARGUMENT_POLICIES["write_note"],
        ),
        ToolDefinition(
            name="dangerous_delete",
            description="Dangerous operation that deletes resources.",
            input_schema={
                "type": "object",
                "properties": {
                    "confirm": {
                        "type": "boolean",
                        "description": "Must be true to execute",
                    },
                    "target": {
                        "type": "string",
                        "description": "Resource to delete",
                    },
                },
                "required": ["confirm", "target"],
                "additionalProperties": False,
            },
            handler=dangerous_delete_tool,
            required_scope=TOOL_SCOPE_MAP["dangerous_delete"],
            argument_policy=TOOL_ARGUMENT_POLICIES["dangerous_delete"],
        ),
    ]
