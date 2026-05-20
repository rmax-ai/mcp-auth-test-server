# Phase 2 Handoff

## Files created/modified

- `src/mcp_auth_test_server/app.py`
  Registers the no-auth MCP router on the main FastAPI app.
- `src/mcp_auth_test_server/mcp/__init__.py`
  Marks the MCP package.
- `src/mcp_auth_test_server/mcp/base.py`
  Adds the reusable JSON-RPC 2.0 dispatcher, built-in MCP methods, tool registry, and protocol error handling.
- `src/mcp_auth_test_server/mcp/tools.py`
  Defines the phase-2 core tools: `echo` and `ping`.
- `src/mcp_auth_test_server/mcp/no_auth.py`
  Implements `POST /mcp/no-auth` with parse-error and JSON-RPC error handling.
- `tests/conftest.py`
  Converts the shared client fixture to a properly managed async `httpx.AsyncClient`.
- `tests/test_smoke.py`
  Reuses the shared client fixture instead of redefining one locally.
- `tests/test_no_auth.py`
  Covers `initialize`, `tools/list`, `tools/call`, and core JSON-RPC error behavior for the no-auth endpoint.

## Key design decisions

- Used one reusable `BaseMCPHandler` instead of embedding logic in the route so later auth schemes can wrap the same MCP behavior.
- Implemented `initialize`, `tools/list`, and `tools/call` as the built-in method surface for the initial MCP server behavior.
- Kept tool implementations in `mcp/tools.py` so future endpoints can share or extend the same tool set.
- Returned HTTP `400` for JSON-RPC parse/request errors and `204` for notifications without an `id`.
- Represented tool results as MCP-style `content` plus `structuredContent` to keep future tool expansion straightforward.

## Architecture notes for Phase 3

- Bearer-token auth should be added as a separate module under `src/mcp_auth_test_server/mcp/`, parallel to `no_auth.py`.
- The bearer route should enforce auth before calling the shared handler, not reimplement the JSON-RPC dispatch logic.
- If more tools are needed later, add them in `mcp/tools.py` or expose endpoint-specific tool lists while still constructing `BaseMCPHandler` with explicit tool definitions.
- Shared auth primitives should live outside `mcp/` in the planned `auth/` package so routes stay thin.

## Gotchas / incomplete items

- `scripts/iterate.sh` had a pre-existing local modification that was intentionally left untouched and was not included in Phase 2 commits.
- The current handler supports single JSON-RPC requests only; batch requests are not implemented yet.
- `content.text` for tool results is currently the Python string form of the returned object. If a stricter MCP client expects serialized JSON text, that can be tightened in a later phase.

## What Phase 3 should build on

- Reuse `BaseMCPHandler` and the existing tool definitions for `/mcp/bearer-token`.
- Add bearer token validation in a dedicated `auth/bearer.py` module and keep the route responsible only for HTTP auth checks plus handler delegation.
- Mirror the `tests/test_no_auth.py` coverage pattern for bearer-token success and auth failure paths, including `WWW-Authenticate` behavior.
