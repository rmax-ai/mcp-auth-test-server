# Testing

This project has three test surfaces:

- Python server tests
- standalone `mcp-auth` CLI tests
- docs site checks and static build verification

## Python server

Run the full suite:

```bash
uv sync --extra dev
uv run pytest tests/ -v
```

Targeted examples:

```bash
uv run pytest tests/test_e2e.py -v
uv run pytest tests/test_mcp_auth_cli.py -v
uv run ruff check src tests
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
