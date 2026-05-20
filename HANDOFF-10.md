# Phase 10 Handoff

## Files created/modified

- `HANDOFF-10.md`
  Phase 10 implementation handoff for the next phase.
- `scripts/test_all_schemes.sh`
  Shell wrapper that runs the standalone live-server client against each auth scheme individually.
- `tests/flow_helpers.py`
  Shared protocol helpers for PKCE, OAuth 1.0a signing, bearer auth headers, JSON-RPC payloads, and redirect parsing.
- `tests/test_client.py`
  Standalone live-server verification client with per-scheme runners for no-auth, bearer token, OAuth 1.0a, OAuth 2.0 auth-code, OAuth 2.0 client-credentials, OAuth 2.1, and dynamic registration.
- `tests/test_e2e.py`
  Comprehensive async end-to-end flow coverage for every auth scheme, including discovery and dynamic registration paths.
- `scripts/iterate.sh`
  Pre-existing local modification that was unintentionally included when following the required `git add -A` workflow.
- `uv.lock`
  Pre-existing untracked lockfile that was unintentionally included when following the required `git add -A` workflow.

## Key design decisions

- Shared wire-level helpers live in `tests/flow_helpers.py` so the pytest e2e coverage and the standalone live client use the same protocol-building logic instead of drifting.
- The new `tests/test_e2e.py` focuses on true scheme-level flows rather than re-checking every single negative edge case already covered by the phase-specific unit tests.
- The standalone client is import-safe even though it lives at `tests/test_client.py`; pytest collects the module, but it exposes only helper functions and a `main()` entrypoint, so it does not add extra test cases or side effects.
- The live client exercises discovery where it matters:
  - OAuth 2.0 auth-code uses authorization-server metadata
  - OAuth 2.1 uses protected-resource metadata and resource-scoped authorization-server metadata

## Architecture notes for the next phase

- `tests/flow_helpers.py` is now the natural place for any new auth-scheme protocol helpers, especially if later phases add DPoP, JWT client auth, token introspection, or revocation flows.
- `tests/test_client.py` already provides a stable per-scheme runner model. If Phase 11 adds more schemes or variants, extend `SCHEMES`, add one `run_*` function, and wire it into `run_scheme()`.
- `scripts/test_all_schemes.sh` is intentionally thin. If later phases need retries, readiness probes, or environment setup, keep the orchestration there and leave protocol assertions in Python.

## Gotchas or incomplete items

- The live client assumes a server is already running and reachable at `http://127.0.0.1:8765` unless `--base-url` is supplied.
- `tests/test_client.py` uses fixed OAuth 1.0a timestamps/nonces that match the server’s permissive skew window. If the mock OAuth 1.0a validation becomes time-stricter later, the live client will need a dynamic timestamp.
- Because the requested workflow mandated `git add -A`, two unrelated pre-existing checkout changes were committed in Phase 10:
  - `scripts/iterate.sh`
  - `uv.lock`
- No dedicated docs page was added for the live client or shell wrapper. Usage is discoverable from the file names and CLI help, but README coverage is still absent.

## What the next phase (11) should build on

- Reuse `tests/test_e2e.py` as the high-signal integration layer for any new auth capability before adding more fragmented tests.
- Build any future manual verification tooling on top of `tests/test_client.py` rather than introducing a second standalone client path.
- If Phase 11 adds server startup orchestration or CI smoke checks, `scripts/test_all_schemes.sh` is the correct entrypoint to evolve into a fuller integration harness.
