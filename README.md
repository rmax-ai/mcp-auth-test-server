# MCP Auth Test Server

A Python MCP test server that exposes distinct endpoints for every major authentication scheme, enabling MCP client developers to test auth integrations in isolation.

## Auth Schemes

| Endpoint | Scheme | Spec |
|----------|--------|------|
| `/mcp/no-auth` | No authentication | — |
| `/mcp/bearer-token` | Static Bearer Token | RFC 6750 |
| `/mcp/oauth-v1` | OAuth 1.0a (Legacy) | RFC 5849 |
| `/mcp/oauth-v2-auth-code` | OAuth 2.0 Authorization Code + PKCE | RFC 6749, RFC 7636 |
| `/mcp/oauth-v2-client-creds` | OAuth 2.0 Client Credentials | RFC 6749 |
| `/mcp/oauth-v21` | OAuth 2.1 Authorization Code + PKCE | OAuth 2.1 (draft) |
| `/register` | Dynamic Client Registration | RFC 7591 |
| `/.well-known/oauth-protected-resource` | Protected Resource Metadata | RFC 9728 |
| `/.well-known/oauth-authorization-server` | Authorization Server Metadata | RFC 8414 |

## Quick Start

```bash
# Install
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run
uvicorn mcp_auth_test_server.app:app --reload --port 8765

# Test
pytest tests/ -v
```

## Architecture

- **FastAPI** application with route mounts per auth scheme
- Each scheme is a self-contained ASGI mount with its own middleware
- In-memory state (tokens, codes, client registrations) — perfect for testing
- OAuth flows include full discovery → register → authorize → token → access

## Usage

See [docs/auth-schemes.md](docs/auth-schemes.md) for detailed walkthroughs of each auth scheme.
