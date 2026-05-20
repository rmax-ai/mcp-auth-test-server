# Phase 3 Handoff

## Files created/modified

- `src/mcp_auth_test_server/app.py`
  Registers the bearer-token MCP router on the main FastAPI app alongside the existing no-auth route.
- `src/mcp_auth_test_server/auth/__init__.py`
  Marks the auth package for shared authentication helpers.
- `src/mcp_auth_test_server/auth/bearer.py`
  Adds static bearer-token validation, `WWW-Authenticate` challenge construction, and env-based token configuration for mock testing.
- `src/mcp_auth_test_server/mcp/bearer_token.py`
  Implements `POST /mcp/bearer-token`, enforcing bearer auth before delegating to the shared JSON-RPC MCP handler.
- `tests/test_bearer_token.py`
  Covers authenticated success, missing header, invalid token, wrong auth scheme, and env-configured token override behavior.

## Key design decisions

- Kept bearer auth as a thin HTTP-layer check in the route and reused `BaseMCPHandler` unchanged for JSON-RPC behavior.
- Used a static mock token model with a simple environment variable override via `MCP_AUTH_TEST_SERVER_BEARER_TOKEN` instead of introducing a settings system this early.
- Returned RFC-style `WWW-Authenticate` bearer challenges on `401` responses, distinguishing malformed requests (`invalid_request`) from bad credentials (`invalid_token`).
- Avoided any external token issuer or persistence layer so tests stay fully offline and deterministic.

## Architecture notes for the next phase

- Phase 4 should add protected resource metadata and auth server metadata under a dedicated `discovery/` package rather than embedding discovery documents in the auth routes.
- The new discovery endpoints should describe `/mcp/bearer-token` as a protected resource and point clients at the future OAuth metadata surface once it exists.
- If more auth schemes need shared HTTP error behavior, consider extracting a small route helper for JSON parse/dispatch handling to reduce duplication between `no_auth.py` and `bearer_token.py`.

## Gotchas / incomplete items

- `scripts/iterate.sh` still has a pre-existing local modification that was intentionally left untouched and was not included in the Phase 3 commits.
- Running project checks in this environment requires `uv run ...`; plain `pytest` and `ruff` executables were not available on `PATH`.
- Bearer token parsing currently accepts the first space-delimited token after `Bearer`; if future phases need stricter header normalization, tighten that in `auth/bearer.py`.

## What Phase 4 should build on

- Add RFC 9728 protected resource metadata for the bearer-token endpoint.
- Add RFC 8414 authorization server metadata that future OAuth phases can extend rather than replace.
- Reuse the bearer auth configuration constants when the discovery documents need to reference supported auth methods or test-server conventions.
