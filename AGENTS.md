# Developer Guide for AI Coding Assistants

## Project Overview

MCP Auth Test Server — a FastAPI application that exposes distinct MCP JSON-RPC
endpoints for each major authentication scheme. Used for testing MCP client auth
implementations.

## Architecture

```
mcp-auth-test-server/
├── src/mcp_auth_test_server/
│   ├── app.py              # FastAPI app, mounts all endpoints
│   ├── mcp/                # MCP JSON-RPC handlers per scheme
│   │   ├── base.py         # Base MCP handler (JSON-RPC)
│   │   ├── no_auth.py      # /mcp/no-auth
│   │   ├── bearer_token.py # /mcp/bearer-token
│   │   ├── oauth_v1.py     # /mcp/oauth-v1
│   │   ├── oauth_v2_3l.py  # /mcp/oauth-v2-auth-code
│   │   ├── oauth_v2_2l.py  # /mcp/oauth-v2-client-creds
│   │   └── oauth_v21.py    # /mcp/oauth-v21
│   ├── auth/               # Auth primitives
│   │   ├── bearer.py       # Bearer token validation
│   │   ├── oauth.py        # Shared OAuth primitives (PKCE, code gen)
│   │   ├── oauth_v1.py     # OAuth 1.0a signature verification
│   │   ├── oauth_v21.py    # OAuth 2.1-specific AS
│   │   ├── token_store.py  # In-memory token/code storage
│   │   └── dynamic_registration.py  # RFC 7591
│   └── discovery/          # RFC 9728 + RFC 8414
│       ├── protected_resource.py
│       └── auth_server_metadata.py
├── tests/
│   ├── test_no_auth.py
│   ├── test_bearer_token.py
│   ├── test_oauth_v1.py
│   ├── test_oauth_v2_2l.py
│   ├── test_oauth_v2_3l.py
│   ├── test_oauth_v21.py
│   ├── test_discovery.py
│   ├── test_dynamic_registration.py
│   └── test_e2e.py
├── docs/
│   └── auth-schemes.md
└── scripts/
    └── iterate.sh
```

## Design Principles

1. **Each scheme is independent** — mounted as a separate sub-application
2. **In-memory state** — no database needed, resets on restart
3. **Spec-compliant** — every endpoint follows the relevant RFC
4. **Testable** — all state is injectable, tests use httpx TestClient

## Key Dependencies

- FastAPI — web framework
- httpx — async HTTP client (for tests)
- pytest — test runner
- ruff — linter + formatter
- pyjwt — JWT token handling
- cryptography — crypto primitives for OAuth 1.0a

## Running Tests

```bash
pytest tests/ -v              # all tests
pytest tests/test_e2e.py -v   # end-to-end tests only
```

## Commands

```bash
make run       # start dev server
make test      # run all tests
make lint      # ruff check
make format    # ruff format
```
