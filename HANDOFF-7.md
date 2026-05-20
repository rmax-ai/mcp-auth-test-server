# Phase 7 Handoff

## Files created/modified

- `HANDOFF-7.md`
  Phase 7 implementation handoff for the next phase.
- `docs/auth-schemes.md`
  Documents the dedicated OAuth 2.1 endpoints, resource-specific discovery URLs, and the mock Phase 7 public client.
- `src/mcp_auth_test_server/app.py`
  Mounts the new OAuth 2.1 router.
- `src/mcp_auth_test_server/auth/oauth.py`
  Adds shared bearer-token audience and issuer validation helpers, plus optional `iss` support for redirect building.
- `src/mcp_auth_test_server/auth/oauth_v21.py`
  Implements OAuth 2.1-specific request validation for S256-only PKCE, implicit-grant rejection, and RFC 8707 resource checks.
- `src/mcp_auth_test_server/auth/token_store.py`
  Extends authorization-code and access-token records with resource, audience, and issuer metadata.
- `src/mcp_auth_test_server/discovery/__init__.py`
  Adds OAuth 2.1 endpoint constants and a helper for resource-specific discovery URLs.
- `src/mcp_auth_test_server/discovery/auth_server_metadata.py`
  Makes authorization-server discovery resource-aware so `/mcp/oauth-v21` advertises its dedicated OAuth 2.1 AS metadata.
- `src/mcp_auth_test_server/discovery/protected_resource.py`
  Makes protected-resource discovery resource-aware and preserves the previous default bearer-token document.
- `src/mcp_auth_test_server/mcp/oauth_v2_3l.py`
  Updates the existing auth-code flow to populate the new authorization-code `resource` field.
- `src/mcp_auth_test_server/mcp/oauth_v21.py`
  Implements `/oauth-v21/authorize`, `/oauth-v21/token`, and `/mcp/oauth-v21`, including `iss` redirects and protected-resource audience/issuer checks.
- `tests/conftest.py`
  Exposes the shared in-memory token store through the test client for targeted token mutation in negative-path tests.
- `tests/test_discovery.py`
  Adds assertions for OAuth 2.1 protected-resource and authorization-server discovery documents.
- `tests/test_oauth_v21.py`
  Adds coverage for plain-PKCE rejection, resource requirement/matching, implicit-grant rejection, `iss` redirect behavior, token `aud`/`iss`, and protected endpoint audience/issuer enforcement.

## Key design decisions

- Implemented OAuth 2.1 as a dedicated authorization server surface at `/oauth-v21/*` instead of layering Phase 7 behavior onto the Phase 5 endpoints. That keeps Phase 5 regression risk low and makes the spec differences explicit in tests and discovery.
- Kept access tokens opaque and continued using the in-memory token store instead of introducing JWT signing. Audience and issuer are stored as token metadata and surfaced in the mock token response as `aud` and `iss`, which is enough for client-auth testing without adding a signing stack.
- Made the existing discovery endpoints resource-aware via an optional `resource` query parameter rather than adding a second set of well-known paths. That preserves backwards compatibility for the bearer-token resource while letting OAuth 2.1 advertise different AS metadata.
- Reused the existing RFC 6750 challenge format and added a `resource_metadata` pointer on the OAuth 2.1 protected endpoint so clients can discover the correct OAuth 2.1 metadata from an auth failure.

## Architecture notes for the next phase

- Resource-aware discovery is now in place and can be extended to other OAuth-backed MCP endpoints instead of relying on one shared protected-resource document.
- `AccessTokenRecord` now has the right shape for future token constraints such as scopes-per-resource, sender-constrained token metadata, or richer issuer/audience assertions.
- `auth/oauth_v21.py` is the right place for any future Phase 8+ OAuth 2.1 validation rules that should stay distinct from the more generic OAuth 2.0 helper module.
- If a later phase needs signed tokens, the current audience/issuer fields can become the source-of-truth claims for JWT minting without changing the protected endpoint validation contract.

## Gotchas or incomplete items

- The mock OAuth 2.1 flow still uses opaque bearer tokens backed by in-memory state; it does not issue JWTs, JWKs, or ID tokens.
- The new resource-aware discovery behavior is query-parameter-driven. Clients that only fetch the bare `/.well-known/oauth-protected-resource` path still get the legacy bearer-token metadata by default.
- `tests/conftest.py` attaches the token store to the test client purely for negative-path mutation tests; that coupling is test-only and should stay out of runtime code.
- `scripts/iterate.sh` had a pre-existing local modification and `uv.lock` was already untracked before Phase 7 work; both were left untouched again.

## What the next phase (8) should build on

- Extend the resource-aware discovery model so every OAuth-protected MCP endpoint can advertise endpoint-specific scopes and auth-server behavior.
- Decide whether the project should keep opaque tokens for all mock flows or introduce optional JWT-backed variants for clients that need claim parsing and key discovery coverage.
- Build additional negative-path coverage around multi-resource handling if Phase 8 adds more than one OAuth 2.1 protected resource or more complex audience rules.
- Consider moving the shared JSON-RPC bearer-protection pattern into a reusable helper if more authenticated MCP routes are added.
