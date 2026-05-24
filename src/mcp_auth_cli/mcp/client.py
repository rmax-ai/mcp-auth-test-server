"""MCP JSON-RPC call helpers."""

from __future__ import annotations

from uuid import uuid4

from mcp_auth_cli.errors import CliError


def build_jsonrpc_payload(
    *,
    method: str,
    params: dict[str, object] | None = None,
    request_id: str | None = None,
) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id or uuid4().hex,
        "method": method,
        "params": params or {},
    }


def call_mcp(client, *, resource_url: str, access_token: str | None, payload: dict[str, object]):
    headers = {}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    response = client.post(resource_url, json=payload, headers=headers)
    if response.status_code >= 400:
        raise CliError(f"MCP call failed: HTTP {response.status_code}: {response.text}")
    body = response.json()
    if "error" in body:
        error = body["error"]
        raise CliError(f"JSON-RPC error {error.get('code')}: {error.get('message')}")
    return body
