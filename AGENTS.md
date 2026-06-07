# Developer Guide for AI Coding Assistants

## Project Overview

MCP Auth Test Server is a FastAPI application that exposes MCP JSON-RPC
endpoints across multiple authentication patterns. It is used to test MCP
client behavior for bearer tokens, OAuth discovery, authorization code + PKCE,
client credentials, device authorization, policy enforcement, and audit/debug
observability.

## Architecture

```text
mcp-auth-test-server/
├── src/mcp_auth_test_server/
│   ├── app.py                 # FastAPI app, mounts all endpoints
│   ├── debug.py               # Debug endpoints (/debug/*) for inspecting OAuth/audit state
│   ├── mcp/                   # MCP JSON-RPC handlers per scheme
│   │   ├── base.py            # BaseMCPHandler, JsonRpcError, ToolDefinition, audit context
│   │   ├── tools.py           # Core MCP tool definitions + scope mappings + argument policies
│   │   ├── policy.py          # Scope-based access control + argument validation
│   │   ├── bearer_token.py    # /mcp/bearer-token (static bearer) + /test-auth/bearer-token/mint
│   │   ├── oauth_v2_3l.py     # /mcp/oauth (auth-code + PKCE)
│   │   ├── oauth_v2_2l.py     # /mcp/oauth-v2-client-creds
│   │   ├── oauth_v21.py       # /mcp/oauth-v21 (OAuth 2.1 specific endpoint)
│   │   └── device_flow.py     # /mcp/device-flow (RFC 8628 device grant)
│   ├── auth/                  # Auth primitives and authorization server
│   │   ├── bearer.py          # Bearer token validation + minting
│   │   ├── oauth.py           # Shared OAuth primitives (PKCE, code/token issuance)
│   │   ├── oauth_v21.py       # OAuth 2.1-specific AS behavior
│   │   ├── token_store.py     # In-memory token/code/client storage + CIMD fixture clients
│   │   ├── dynamic_registration.py  # RFC 7591 dynamic registration
│   │   ├── approval.py        # Approval mode model (MANUAL/AUTO_APPROVE/AUTO_DENY)
│   │   ├── audit.py           # Structured audit event recording
│   │   └── cimd.py            # CIMD fixture client resolution
│   └── discovery/             # RFC 9728 + RFC 8414
│       ├── protected_resource.py
│       └── auth_server_metadata.py
├── tests/
│   ├── test_bearer_token.py
│   ├── test_oauth_v2_2l.py
│   ├── test_oauth_v2_3l.py
│   ├── test_oauth_v21.py
│   ├── test_device_flow.py
│   ├── test_debug.py
│   ├── test_discovery.py
│   ├── test_dynamic_registration.py
│   ├── test_openapi_docs.py
│   ├── test_smoke.py
│   ├── test_e2e.py
│   ├── test_mcp_auth_cli.py
│   ├── test_client.py
│   ├── flow_helpers.py
│   └── conftest.py
├── docs/
│   ├── architecture.md
│   ├── auth-schemes.md
│   ├── cli.md
│   ├── testing.md
│   ├── deployment.md
│   └── site/                  # SvelteKit + mdsvex docs website
├── scripts/
│   └── iterate.sh
└── .github/workflows/
    └── deploy-docs.yml
```

## Design Principles

1. **Each auth surface stays explicit** - bearer and OAuth behaviors remain
   visible as separate routers and modules rather than being hidden behind one
   abstraction.
2. **In-memory state** - no database is required; authorization codes, device
   codes, clients, tokens, approvals, and audit events reset between test runs.
3. **State exposed via debug endpoints** - every OAuth operation is observable
   through the `/debug/*` surface.
4. **Policy-aware tool model** - tool definitions carry scope requirements,
   argument validation rules, and environment-gated dangerous-operation
   controls; the current mounted handlers actively enforce argument policies.
5. **Audit trail** - structured audit events are recorded for registrations,
   approvals, authorization codes, token issuance, and MCP requests with
   redacted token/code hashes.
6. **Spec-oriented behavior** - discovery, bearer challenges, PKCE, dynamic
   registration, device flow, and resource indicators are modeled after the
   relevant RFCs.
7. **Testable by design** - shared state is injectable and resettable, and the
   test suite exercises HTTP, CLI, discovery, OpenAPI, and end-to-end flows.

## Key Dependencies

- FastAPI - web framework
- httpx - async HTTP client used by tests and the CLI
- uv - dependency and command runner
- pytest - test runner
- ruff - linter + formatter
- pyjwt - JWT token handling
- cryptography - crypto primitives used by auth-related flows

## Environment Setup

```bash
uv sync --dev
```

## Debug Endpoints

The default app mounts a debug router for inspecting the in-memory OAuth state:

- `/debug/authorizations` - issued authorization codes exposed as redacted
  hashes with client, scope, resource, and expiry metadata
- `/debug/approvals` - recorded approval decisions with mode, timestamp, and
  admin-scope confirmation status
- `/debug/tokens` - issued access tokens exposed as redacted hashes with grant,
  audience, issuer, scope, and expiry metadata
- `/debug/clients` - registered clients with grant/auth method metadata and
  redacted secrets
- `/debug/audit` - structured audit events for registration, approval,
  authorization-code issuance, token issuance, and MCP activity

There is no separate `/debug/code-exchange` route in the current app. Code
issuance and exchange state is visible through `/debug/authorizations` and
`/debug/audit`.

## Standalone CLI

This repo also ships a standalone `mcp-auth` CLI in `src/mcp_auth_cli/`.
Use it when you need to exercise MCP auth flows from a user/client perspective
rather than by calling test endpoints manually.

Common commands:

```bash
uv run mcp-auth discover http://127.0.0.1:8765/mcp/oauth
uv run mcp-auth login http://127.0.0.1:8765/mcp/oauth
uv run mcp-auth call http://127.0.0.1:8765/mcp/oauth initialize
uv run mcp-auth profile list
```

The CLI supports bearer, authorization-code + PKCE, device, and
client-credentials flows. It stores reusable local profiles and automatically
refreshes or reacquires tokens when the selected auth mode supports it.

## Docs Website

The repo also includes a static docs app in `docs/site/`. It is a separate
Node-based project built with SvelteKit, `@sveltejs/adapter-static`, and
mdsvex, and it is deployed to GitHub Pages from `.github/workflows/deploy-docs.yml`.

Common docs-site commands:

```bash
cd docs/site
npm install
npm run dev
npm run check
npm run build
```

## Running Tests

```bash
uv run pytest tests/ -v                    # all tests
uv run pytest tests/test_e2e.py -v         # end-to-end coverage
uv run pytest tests/test_mcp_auth_cli.py -v
uv run pytest tests/test_openapi_docs.py -v
```

## Commands

```bash
uv run uvicorn mcp_auth_test_server.app:app --reload --port 8765  # start dev server
uv run pytest tests/ -v                                           # run all tests
uv run ruff check src/ tests/                                     # ruff check
uv run ruff format src/ tests/                                    # ruff format

make run       # convenience wrapper for the dev server
make test      # convenience wrapper for test suite
make lint      # convenience wrapper for ruff check
make format    # convenience wrapper for ruff format
```
