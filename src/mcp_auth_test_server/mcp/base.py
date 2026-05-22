"""Shared JSON-RPC handling for MCP endpoints."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

JsonObject = dict[str, Any]
ToolHandler = Callable[[JsonObject], Awaitable[JsonObject]]

logger = logging.getLogger("mcp_auth_test_server.audit")


@dataclass(slots=True)
class ToolDefinition:
    """MCP tool metadata and implementation."""

    name: str
    description: str
    input_schema: JsonObject
    handler: ToolHandler

    def as_mcp_tool(self) -> JsonObject:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


@dataclass(slots=True)
class RequestAuditContext:
    """Audit context captured for an MCP request."""

    endpoint: str
    auth_scheme: str
    caller: str
    source_ip: str = "-"
    client_id: str = "-"
    scope: str = "-"
    grant_type: str = "-"
    audience: str = "-"
    issuer: str = "-"


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
        self,
        payload: Any,
        *,
        audit_context: RequestAuditContext | None = None,
    ) -> tuple[int | None, JsonObject | None]:
        """Validate and dispatch a JSON-RPC request body."""

        if not isinstance(payload, dict):
            raise JsonRpcError(-32600, "Invalid Request")

        request_id = payload.get("id")
        try:
            self._validate_request(payload)

            method = payload["method"]
            params = payload.get("params")
            if params is None:
                params = {}
            if not isinstance(params, dict):
                raise JsonRpcError(-32602, "Invalid params")

            self._log_request(
                audit_context=audit_context,
                request_id=request_id,
                method=method,
                params=params,
            )
            result = await self._dispatch(method=method, params=params)
        except JsonRpcError as exc:
            self._log_error(
                audit_context=audit_context,
                request_id=request_id,
                method=payload.get("method"),
                error=exc,
            )
            raise

        if request_id is None:
            return None, None
        return 200, {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _validate_request(self, payload: JsonObject) -> None:
        if payload.get("jsonrpc") != "2.0":
            raise JsonRpcError(-32600, "Invalid Request")
        if not isinstance(payload.get("method"), str):
            raise JsonRpcError(-32600, "Invalid Request")

    async def _dispatch(self, *, method: str, params: JsonObject) -> JsonObject:
        if method == "initialize":
            return self._handle_initialize()
        if method == "notifications/initialized":
            return {}
        if method == "ping":
            return {}
        if method == "tools/list":
            return self._handle_tools_list()
        if method == "tools/call":
            return await self._handle_tools_call(params)
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

    def _handle_tools_list(self) -> JsonObject:
        return {"tools": [tool.as_mcp_tool() for tool in self._tools.values()]}

    async def _handle_tools_call(self, params: JsonObject) -> JsonObject:
        name = params.get("name")
        arguments = params.get("arguments", {})

        if not isinstance(name, str):
            raise JsonRpcError(-32602, "Invalid params")
        if not isinstance(arguments, dict):
            raise JsonRpcError(-32602, "Invalid params")

        tool = self._tools.get(name)
        if tool is None:
            raise JsonRpcError(-32601, f"Unknown tool: {name}")

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

    def _log_request(
        self,
        *,
        audit_context: RequestAuditContext | None,
        request_id: Any,
        method: str,
        params: JsonObject,
    ) -> None:
        context = audit_context or RequestAuditContext(
            endpoint="-",
            auth_scheme="unknown",
            caller="unknown",
        )
        tool_name = params.get("name") if method == "tools/call" else "-"
        argument_keys: list[str] = []
        if method == "tools/call":
            arguments = params.get("arguments", {})
            if isinstance(arguments, dict):
                argument_keys = sorted(str(key) for key in arguments)

        logger.info(
            "mcp request endpoint=%s auth_scheme=%s caller=%s client_id=%s source_ip=%s "
            "request_id=%s method=%s tool_name=%s argument_keys=%s scope=%s "
            "grant_type=%s audience=%s issuer=%s",
            context.endpoint,
            context.auth_scheme,
            context.caller,
            context.client_id,
            context.source_ip,
            request_id,
            method,
            tool_name,
            argument_keys,
            context.scope,
            context.grant_type,
            context.audience,
            context.issuer,
        )

    def _log_error(
        self,
        *,
        audit_context: RequestAuditContext | None,
        request_id: Any,
        method: Any,
        error: JsonRpcError,
    ) -> None:
        context = audit_context or RequestAuditContext(
            endpoint="-",
            auth_scheme="unknown",
            caller="unknown",
        )
        logger.warning(
            "mcp request failed endpoint=%s auth_scheme=%s caller=%s client_id=%s "
            "source_ip=%s request_id=%s method=%s error_code=%s error_message=%s",
            context.endpoint,
            context.auth_scheme,
            context.caller,
            context.client_id,
            context.source_ip,
            request_id,
            method,
            error.code,
            error.message,
        )
