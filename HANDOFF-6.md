# Phase 6 Handoff

## Files created/modified

- `HANDOFF-6.md`
  Phase 6 implementation handoff for the next phase.
- `docs/auth-schemes.md`
  Corrects the OAuth endpoint paths and documents the mock client-credentials test client.
- `src/mcp_auth_test_server/app.py`
  Mounts the new Phase 6 OAuth 2.0 client-credentials MCP router.
- `src/mcp_auth_test_server/auth/oauth.py`
  Adds shared OAuth grant-type constants and a helper that enforces which grant issued a bearer token.
- `src/mcp_auth_test_server/auth/token_store.py`
  Adds a mock in-memory client-credentials registry and records the OAuth grant type on issued access tokens.
- `src/mcp_auth_test_server/discovery/auth_server_metadata.py`
  Updates RFC 8414 metadata to advertise both `authorization_code` and `client_credentials`, plus `client_secret_post`.
- `src/mcp_auth_test_server/mcp/oauth_v2_2l.py`
  Implements `/mcp/oauth-v2-client-creds` and requires a token issued via the client-credentials grant.
- `src/mcp_auth_test_server/mcp/oauth_v2_3l.py`
  Extends `/oauth/token` to support `client_credentials` while preserving the Phase 5 auth-code flow, and tightens the auth-code MCP endpoint to reject the wrong token grant.
- `tests/test_discovery.py`
  Updates discovery assertions for the expanded token endpoint metadata.
- `tests/test_oauth_v2_2l.py`
  Adds client-credentials token, invalid-client, protected-endpoint, and cross-grant rejection coverage.
- `tests/test_oauth_v2_3l.py`
  Adds a regression test proving the auth-code MCP endpoint rejects a client-credentials token.

## Key design decisions

- Reused the existing `/oauth/token` route for both OAuth grants instead of creating a second token endpoint. That keeps the mock authorization server closer to real deployments and avoids duplicated token response logic.
- Stored mock client credentials in the existing in-memory `OAuthTokenStore` module so all mock OAuth state still resets between tests and on process restart.
- Added `grant_type` to `AccessTokenRecord` and enforced it at the protected MCP endpoints. That keeps `/mcp/oauth-v2-auth-code` and `/mcp/oauth-v2-client-creds` behavior explicit and prevents one grant from being silently accepted by the other endpoint.
- Used `client_secret_post` for the mock machine-to-machine client, matching the issue requirements that credentials be sent as `client_id` and `client_secret` form fields to `/oauth/token`.

## Architecture notes for the next phase

- Phase 7 can build on the grant-type-aware token model and extend `AccessTokenRecord` further for OAuth 2.1 fields like `resource`, `audience`, or issuer metadata.
- The shared helpers in `auth/oauth.py` are now the right place to centralize any future token-usage checks beyond grant type, such as scope enforcement per protected resource.
- If Phase 7 adds more than one OAuth protected resource, the protected-resource discovery document should likely become resource-specific instead of remaining a single shared document.

## Gotchas or incomplete items

- `/.well-known/oauth-protected-resource` still returns a single shared document that points at `/mcp/bearer-token`. That was already a known limitation from Phase 5 and is still the main discovery mismatch for the OAuth endpoints.
- The client-credentials mock registry is intentionally static for now: `phase-6-service-client` / `phase-6-service-secret`.
- `registration_endpoint` is still advertised in discovery as a placeholder and is not implemented yet.
- `scripts/iterate.sh` had a pre-existing local modification and `uv.lock` was already untracked before Phase 6 work; both were left untouched again.

## What the next phase (7) should build on

- Implement OAuth 2.1 security rules on top of the existing auth-code flow instead of replacing it.
- Refactor protected-resource discovery so each OAuth MCP endpoint can advertise the correct resource URL and scope requirements.
- Move from grant-only token validation toward resource-aware validation so the 2.1 flow can enforce `resource` or `aud` style constraints cleanly.
