# Phase 4 Handoff

## Files created/modified

- `src/mcp_auth_test_server/app.py`
  Registers the new OAuth discovery routers on the main FastAPI app.
- `src/mcp_auth_test_server/auth/bearer.py`
  Extends bearer auth challenge rendering so `401` responses can advertise protected resource metadata.
- `src/mcp_auth_test_server/discovery/__init__.py`
  Defines shared well-known paths, mock OAuth endpoint paths, mock scopes, and absolute-URL helpers.
- `src/mcp_auth_test_server/discovery/protected_resource.py`
  Implements `GET /.well-known/oauth-protected-resource` with a mock RFC 9728 metadata document for `/mcp/bearer-token`.
- `src/mcp_auth_test_server/discovery/auth_server_metadata.py`
  Implements `GET /.well-known/oauth-authorization-server` with a mock RFC 8414 metadata document that future OAuth phases can extend.
- `src/mcp_auth_test_server/mcp/bearer_token.py`
  Adds `resource_metadata` to bearer `WWW-Authenticate` challenges on auth failures.
- `tests/test_bearer_token.py`
  Verifies bearer `401` responses include the protected resource metadata URL.
- `tests/test_discovery.py`
  Covers both well-known discovery endpoints and their mock document payloads.

## Key design decisions

- Kept discovery logic in a dedicated `discovery/` package instead of embedding document builders in auth routes.
- Returned absolute URLs in discovery documents and `WWW-Authenticate` metadata so MCP clients can resolve resources directly from any host/base URL.
- Used mock OAuth metadata only: the RFC 8414 document advertises placeholder authorization, token, and registration endpoints without requiring Phase 5+ OAuth implementations to exist yet.
- Left bearer token validation itself unchanged and only extended challenge serialization, which keeps the auth enforcement path small and easy to reuse.

## Architecture notes for the next phase

- Phase 5 should introduce real OAuth authorization-code + PKCE endpoints behind the paths currently advertised in the auth server metadata, or update the metadata paths in one place if the route layout changes.
- If Phase 5 adds shared OAuth configuration, the constants in `discovery/__init__.py` are the right place to centralize issuer-relative paths and supported scopes.
- Once multiple protected MCP resources exist, `protected_resource.py` will likely need either per-resource metadata documents or a small builder that can generate documents from route-specific configuration.

## Gotchas or incomplete items

- The authorization server metadata is intentionally mock-only in this phase; the advertised OAuth endpoints do not exist yet.
- `scripts/iterate.sh` still has a pre-existing local modification that was intentionally left untouched.
- Running checks in this environment still requires `uv run ...`; invoking `uv` also produced an untracked `uv.lock`, which was left out of commits.

## What Phase 5 should build on

- Implement the OAuth 2.0 authorization code + PKCE flow using the discovery URLs already exposed here.
- Replace the mock authorization/token endpoint behavior with real FastAPI handlers while preserving the RFC 8414 document contract.
- Reuse the bearer discovery wiring pattern so future auth-protected endpoints can advertise `resource_metadata` consistently on `401` responses.
