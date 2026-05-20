# Phase 8 Handoff

## Files created/modified

- `HANDOFF-8.md`
  Phase 8 implementation handoff for the next phase.
- `docs/auth-schemes.md`
  Documents the mock OAuth 1.0a consumer credentials for the legacy endpoint.
- `src/mcp_auth_test_server/app.py`
  Mounts the new OAuth 1.0a MCP router.
- `src/mcp_auth_test_server/auth/oauth_v1.py`
  Implements OAuth 1.0a Authorization-header parsing, HMAC-SHA1 signature validation, consumer credential lookup, timestamp checks, and in-memory nonce replay protection.
- `src/mcp_auth_test_server/mcp/oauth_v1.py`
  Implements the `/mcp/oauth-v1` protected MCP endpoint and maps OAuth 1.0a validation failures to `401` responses with an `OAuth` challenge header.
- `tests/conftest.py`
  Resets the OAuth 1.0a nonce store between tests so replay coverage stays deterministic.
- `tests/test_oauth_v1.py`
  Covers valid OAuth 1.0a requests, missing headers, invalid signatures, nonce replay rejection, and stale timestamps.

## Key design decisions

- Implemented OAuth 1.0a as a dedicated legacy endpoint at `/mcp/oauth-v1`, mirroring the project’s one-endpoint-per-scheme structure instead of mixing legacy auth into the bearer or OAuth 2.x handlers.
- Kept signing limited to RFC 5849 HMAC-SHA1 over the Authorization header plus request URL, which is enough for MCP client-auth testing without introducing request-body form signing or token-secret flows.
- Used a small in-memory nonce store with timestamp skew enforcement rather than persisting replay state, matching the rest of the test server’s restart-resets-state model.
- Reused the existing JSON-RPC handler contract so the new auth layer only gates access and does not fork MCP behavior from the other endpoints.

## Architecture notes for the next phase

- `auth/oauth_v1.py` now owns the legacy request-signing rules. If later phases need stricter RFC 5849 coverage such as form-encoded parameter signing or token-secret support, that module is the extension point.
- The nonce store is intentionally isolated from the OAuth 2.x token store. If a future phase needs generic replay/state helpers, those two in-memory state models could be unified behind a shared interface.
- `/mcp/oauth-v1` currently validates against one mock consumer key/secret pair. If broader matrix testing is needed later, the credential lookup can expand to a small configured registry without changing the route contract.

## Gotchas or incomplete items

- The OAuth 1.0a flow is intentionally legacy and minimal: it does not implement request tokens, access-token exchange, or token-secret-based signing.
- Signature normalization currently covers query parameters plus OAuth Authorization-header parameters, which matches the current JSON POST endpoint usage. It does not yet fold in `application/x-www-form-urlencoded` request-body parameters.
- `scripts/iterate.sh` had a pre-existing local modification and `uv.lock` was already untracked before Phase 8 work; both were left untouched again.

## What the next phase (9) should build on

- Phase 9 should build the dynamic client registration surface on top of the existing OAuth 2.x authorization-server structure rather than adding a separate parallel auth model.
- The existing discovery and OAuth helper modules already provide a clear place to advertise and enforce client-registration metadata once `/register` is implemented.
- If Phase 9 introduces new client records into shared state, preserve the current test-fixture reset pattern so registration tests stay isolated and offline.
