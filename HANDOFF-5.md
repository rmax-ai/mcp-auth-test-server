# Phase 5 Handoff

## Files created/modified

- `src/mcp_auth_test_server/app.py`
  Registers the Phase 5 OAuth 2.0 authorization-code + PKCE routes.
- `src/mcp_auth_test_server/auth/oauth.py`
  Adds OAuth request validation, scope checks, PKCE S256 verification, redirect helpers, and issued access-token validation.
- `src/mcp_auth_test_server/auth/token_store.py`
  Adds an in-memory store for authorization codes and OAuth access tokens with TTL handling and reset support.
- `src/mcp_auth_test_server/discovery/auth_server_metadata.py`
  Updates RFC 8414 metadata to reflect the real Phase 5 auth-code flow and current token endpoint auth behavior.
- `src/mcp_auth_test_server/mcp/oauth_v2_3l.py`
  Implements `/oauth/authorize`, simulated browser consent at `/oauth/authorize/consent`, `/oauth/token`, and the protected `/mcp/oauth-v2-auth-code` MCP endpoint.
- `tests/conftest.py`
  Resets the shared OAuth in-memory store before and after each test.
- `tests/test_discovery.py`
  Updates auth server metadata assertions for the now-real auth-code flow.
- `tests/test_oauth_v2_3l.py`
  Adds end-to-end coverage for consent, PKCE validation, token exchange, one-time code use, and protected MCP access.

## Key design decisions

- Kept Phase 5 state entirely in memory with a dedicated `OAuthTokenStore` so the server remains restart-resettable and tests stay offline.
- Used a public-client auth-code flow with `token_endpoint_auth_methods_supported: ["none"]` because this phase is specifically PKCE-based and does not yet introduce client secrets or registration.
- Implemented simulated consent as a simple HTML page plus a POST approval/deny step, while also supporting `auto_approve=true` for compact automated tests.
- Consumed authorization codes before PKCE verification so the mock server enforces one-time code use even when the verifier is wrong.

## Architecture notes for the next phase

- Phase 6 can reuse `OAuthTokenStore` for client-credentials access tokens instead of creating a separate bearer-token path.
- If Phase 6 introduces multiple OAuth protected resources, the protected-resource discovery document should likely become resource-specific instead of always describing `/mcp/bearer-token`.
- The OAuth helper module is the right place to centralize future token parsing, scope checks, and shared RFC error rendering across OAuth phases.

## Gotchas or incomplete items

- `registration_endpoint` is still advertised in discovery as a placeholder and is not implemented yet.
- The consent page is intentionally minimal HTML for testability; it simulates a browser approval step but is not a real user-facing UI.
- `scripts/iterate.sh` had a pre-existing local modification and `uv.lock` was untracked before this phase; both were left out of Phase 5 commits.

## What Phase 6 should build on

- Add `/mcp/oauth-v2-client-creds` plus a `client_credentials` token issuance path that reuses the access-token validation introduced here.
- Extend the authorization server metadata to advertise both `authorization_code` and `client_credentials` once the new token flow exists.
- Introduce a shared concept of protected-resource scope requirements so each MCP endpoint can declare the scopes its issued tokens must contain.
