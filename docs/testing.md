# Testing

This project has three test surfaces:

- Python server tests
- standalone `mcp-auth` CLI tests
- docs site checks and static build verification

## Python server

Run the full suite:

```bash
uv sync --dev
uv run pytest tests/ -v
```

Targeted examples:

```bash
uv run pytest tests/test_e2e.py -v
uv run pytest tests/test_mcp_auth_cli.py -v
uv run pytest tests/test_openapi_docs.py -v
uv run ruff check src tests
```

Current test layout:

```text
tests/test_smoke.py                 # Basic server startup and health
tests/test_bearer_token.py          # Static bearer endpoint
tests/test_oauth_v2_3l.py           # OAuth auth-code + PKCE server logic
tests/test_oauth_v2_2l.py           # OAuth client-credentials server logic
tests/test_oauth_v21.py             # OAuth 2.1 specific server logic
tests/test_device_flow.py           # Device authorization grant
tests/test_debug.py                 # Debug endpoint inspection
tests/test_discovery.py             # Discovery endpoint behavior
tests/test_dynamic_registration.py  # Dynamic client registration
tests/test_openapi_docs.py          # OpenAPI schema + docs UI
tests/test_client.py                # Client-side mcp-auth CLI unit tests
tests/test_mcp_auth_cli.py          # End-to-end CLI integration tests
tests/test_e2e.py                   # Full end-to-end server flow tests
tests/flow_helpers.py               # Shared test utilities
tests/conftest.py                   # Pytest fixtures
```

## CLI verification

Start the server:

```bash
uv run uvicorn mcp_auth_test_server.app:app --reload --port 8765
```

In another terminal:

```bash
uv run mcp-auth discover http://127.0.0.1:8765/mcp/oauth
uv run mcp-auth login http://127.0.0.1:8765/mcp/oauth
uv run mcp-auth call http://127.0.0.1:8765/mcp/oauth initialize
```

For flow-specific sequences, see [cli.md](./cli.md) and
[auth-schemes.md](./auth-schemes.md).

## Inspecting debug state during tests

The server keeps OAuth and audit state in memory and exposes it through
read-only `/debug/*` endpoints. This is useful when you want to confirm what a
test or manual flow just did without attaching a debugger.

Useful endpoints:

- `/debug/authorizations` for issued auth codes as redacted hashes
- `/debug/approvals` for consent decisions and approval modes
- `/debug/tokens` for issued access tokens as redacted hashes
- `/debug/clients` for seeded and dynamically registered client metadata
- `/debug/audit` for structured audit events across registration, approval, token issuance, and MCP requests

Example inspection commands:

```bash
curl http://127.0.0.1:8765/debug/tokens
curl http://127.0.0.1:8765/debug/clients
curl http://127.0.0.1:8765/debug/audit
```

The debug responses never expose raw authorization codes, access tokens, or
client secrets. They return redacted hashes or metadata summaries instead.

## Docs site

The docs site is validated separately because it is a Node-based subproject.

```bash
cd docs/site
npm install
npm run check
npm run build
```

## What should be run after changes

### Server behavior changes

Run:

```bash
uv run ruff check src tests
uv run pytest tests/ -v
```

### CLI changes

Run:

```bash
uv run ruff check src tests
uv run pytest tests/test_mcp_auth_cli.py -v
```

### Docs website changes

Run:

```bash
cd docs/site
npm run check
npm run build
```
