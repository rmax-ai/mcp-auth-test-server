# Phase 9 Handoff

## Files created/modified

- `HANDOFF-9.md`
  Phase 9 implementation handoff for the next phase.
- `docs/auth-schemes.md`
  Corrects the dynamic registration endpoint path to `/oauth/register` and documents the supported mock registration modes.
- `src/mcp_auth_test_server/app.py`
  Mounts the dynamic client registration router.
- `src/mcp_auth_test_server/auth/dynamic_registration.py`
  Implements the mock RFC 7591 registration endpoint, registration payload validation, RFC-style error responses, and helper validation for registered clients across authorize and token flows.
- `src/mcp_auth_test_server/auth/token_store.py`
  Extends the in-memory OAuth store with client records, seeded legacy clients from earlier phases, dynamic client persistence, and shared client-secret validation.
- `src/mcp_auth_test_server/mcp/oauth_v2_3l.py`
  Requires registered clients for authorization-code and client-credentials flows and enforces per-client token endpoint auth policy during token exchange.
- `src/mcp_auth_test_server/mcp/oauth_v21.py`
  Requires registered public clients for OAuth 2.1 authorization-code flows and enforces `token_endpoint_auth_method=none` on the OAuth 2.1 token endpoint.
- `tests/test_dynamic_registration.py`
  Covers successful public and confidential registrations, end-to-end use of registered clients in OAuth 2.0 and OAuth 2.1 flows, and rejection of unsupported registration metadata.

## Key design decisions

- Dynamic registration is implemented as a mock RFC 7591 surface at `/oauth/register`, but it feeds the same shared in-memory client registry used by `/oauth/authorize`, `/oauth/token`, and `/oauth-v21/*` rather than introducing a second source of truth.
- Existing phase fixture clients (`phase-5-public-client`, `phase-6-service-client`, `phase-7-public-client`) are now seeded into the client registry on reset so older tests stay stable while new dynamic registrations use the same validation path.
- The supported registration model is intentionally small and explicit:
  - Public auth-code clients use `token_endpoint_auth_method=none`
  - Confidential client-credentials clients use `token_endpoint_auth_method=client_secret_post`
  - Only `authorization_code`, `client_credentials`, and `response_type=code` are supported
- OAuth 2.1 is stricter than the generic OAuth 2.0 AS:
  - Registered clients must be public (`none`)
  - Supplying a client secret to `/oauth-v21/token` is rejected

## Architecture notes for the next phase

- `auth/dynamic_registration.py` now owns both registration payload validation and client-policy enforcement. If future phases add registration management endpoints (read/update/delete) or richer metadata, that module is the extension point.
- `auth/token_store.py` now contains three state types: clients, authorization codes, and access tokens. If later phases need persistence or more advanced fixtures, this is the place to split or abstract storage concerns.
- The OAuth endpoints no longer treat `client_id` as free-form input; they consult registered client metadata before issuing codes or tokens. Future auth work should preserve that invariant.

## Gotchas or incomplete items

- The RFC 7591 implementation is intentionally mock-sized. It does not implement registration access tokens, client read/update/delete, software statements, JWKS metadata, or advanced auth methods such as `private_key_jwt`.
- The default registration behavior is biased toward browser/public clients:
  - If `grant_types` is omitted, it defaults to `authorization_code`
  - If `token_endpoint_auth_method` is omitted, it defaults to `none`
- Client IDs and secrets are in-memory only and reset with the test process, matching the rest of the server’s ephemeral-state model.
- `scripts/iterate.sh` had a pre-existing local modification and `uv.lock` was already untracked before Phase 9 work; both were left untouched again.

## What the next phase (10) should build on

- Build any additional OAuth authorization-server capabilities on top of the shared client registry instead of adding per-endpoint client configuration.
- If Phase 10 needs richer discovery metadata, registration fields, or client authentication modes, extend `auth/dynamic_registration.py` first and then thread the new rules through the existing authorize/token validators.
- If the next phase introduces persistent backing storage or configuration-driven fixtures, preserve the current test reset behavior so offline test isolation remains deterministic.
