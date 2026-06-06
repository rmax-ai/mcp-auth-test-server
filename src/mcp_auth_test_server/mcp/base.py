"""Shared JSON-RPC handling for MCP endpoints."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from mcp_auth_test_server.mcp.policy import (
    check_argument_policy,
    check_tool_scope,
    filter_tools_by_scope,
)

JsonObject = dict[str, Any]
ToolHandler = Callable[[JsonObject], Awaitable[JsonObject]]


@dataclass(slots=True)
class ArgumentConstraint:
    """Constraint on a tool argument value."""

    param: str
    constraint_type: str  # "required", "min_length", "max_length", "pattern", "equals"
    value: Any


@dataclass(slots=True)
class ToolArgumentPolicy:
    """Argument validation policy for a tool."""

    required_params: list[str]
    constraints: list[ArgumentConstraint]
    blocked_patterns: list[str]  # content patterns to reject
    environment_flag: str | None = None  # env var that must be set to allow


@dataclass(slots=True)
class ToolDefinition:
    """MCP tool metadata and implementation."""

    name: str
    description: str
    input_schema: JsonObject
    handler: ToolHandler
    required_scope: str = ""
    argument_policy: ToolArgumentPolicy | None = None

    def as_mcp_tool(self) -> JsonObject:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class JsonRpcError(Exception):
    """JSON-RPC error payload."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def as_response(self, request_id: Any) -> JsonObject:
        error: JsonObject = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        return {"jsonrpc": "2.0", "id": request_id, "error": error}


class BaseMCPHandler:
    """Minimal MCP server built on top of JSON-RPC 2.0."""

    protocol_version = "2025-03-26"

    def __init__(
        self,
        *,
        server_name: str,
        server_version: str,
        instructions: str,
        tools: list[ToolDefinition],
    ) -> None:
        self.server_name = server_name
        self.server_version = server_version
        self.instructions = instructions
        self._tools = {tool.name: tool for tool in tools}

    async def handle_message(
        self, payload: Any, *, token_scope: str | None = None
    ) -> tuple[int | None, JsonObject | None]:
        """Validate and dispatch a JSON-RPC request body.

        When *token_scope* is provided the handler enforces scope-based
        access control and tool argument policies.
        """

        if not isinstance(payload, dict):
            raise JsonRpcError(-32600, "Invalid Request")

        request_id = payload.get("id")
        self._validate_request(payload)

        method = payload["method"]
        params = payload.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise JsonRpcError(-32602, "Invalid params")

        result = await self._dispatch(method=method, params=params, token_scope=token_scope)
        if request_id is None:
            return None, None
        return 200, {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _validate_request(self, payload: JsonObject) -> None:
        if payload.get("jsonrpc") != "2.0":
            raise JsonRpcError(-32600, "Invalid Request")
        if not isinstance(payload.get("method"), str):
            raise JsonRpcError(-32600, "Invalid Request")

    async def _dispatch(
        self, *, method: str, params: JsonObject, token_scope: str | None = None
    ) -> JsonObject:
        if method == "initialize":
            return self._handle_initialize()
        if method == "tools/list":
            return self._handle_tools_list(token_scope=token_scope)
        if method == "tools/call":
            return await self._handle_tools_call(params, token_scope=token_scope)
        raise JsonRpcError(-32601, "Method not found")

    def _handle_initialize(self) -> JsonObject:
        return {
            "protocolVersion": self.protocol_version,
            "serverInfo": {
                "name": self.server_name,
                "version": self.server_version,
            },
            "capabilities": {
                "tools": {},
            },
            "instructions": self.instructions,
        }

    def _handle_tools_list(self, *, token_scope: str | None = None) -> JsonObject:
        allowed = filter_tools_by_scope(self._tools, token_scope)
        return {"tools": [tool.as_mcp_tool() for tool in allowed]}

    async def _handle_tools_call(
        self, params: JsonObject, *, token_scope: str | None = None
    ) -> JsonObject:
        name = params.get("name")
        arguments = params.get("arguments", {})

        if not isinstance(name, str):
            raise JsonRpcError(-32602, "Invalid params")
        if not isinstance(arguments, dict):
            raise JsonRpcError(-32602, "Invalid params")

        tool = self._tools.get(name)
        if tool is None:
            raise JsonRpcError(-32601, f"Unknown tool: {name}")

        check_tool_scope(tool, token_scope)

        if tool.argument_policy is not None:
            check_argument_policy(
                tool.argument_policy,
                arguments,
                tool_name=tool.name,
            )

        structured_content = await tool.handler(arguments)
        return {
            "content": [
                {
                    "type": "text",
                    "text": str(structured_content),
                }
            ],
            "structuredContent": structured_content,
            "isError": False,
        }
