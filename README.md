# MCP Auth Test Server

A Python MCP test server for exercising two auth surfaces on the same service:
- `/mcp/oauth` for OAuth-issued bearer tokens
- `/mcp/bearer-token` for static test bearer tokens

## Endpoints

### MCP protected resources

| Endpoint | Purpose |
|----------|---------|
| `/mcp/oauth` | Canonical OAuth-protected MCP JSON-RPC endpoint |
| `/mcp/bearer-token` | Static bearer-token MCP JSON-RPC endpoint |

### OAuth authorization server

| Endpoint | Purpose |
|----------|---------|
| `/oauth/authorize` | Authorization endpoint for auth code + PKCE |
| `/oauth/token` | Token endpoint for auth code, refresh token, client credentials, and device code |
| `/oauth/device/authorize` | Device authorization endpoint |
| `/oauth/device/verify` | Mock verification UI for device flow |
| `/oauth/device/verify/consent` | Mock device verification form handler |
| `/oauth/register` | Dynamic client registration |
| `/.well-known/oauth-protected-resource` | Protected resource metadata |
| `/.well-known/oauth-authorization-server` | Authorization server metadata |

### Test/helper endpoints

| Endpoint | Purpose |
|----------|---------|
| `/test-auth/bearer-token/mint` | Mint a short-lived static bearer token for `/mcp/bearer-token` |
| `/health` | Health check |
| `/docs` | Swagger UI |
| `/redoc` | ReDoc |

## Supported OAuth Flows

This server supports the main OAuth flows relevant to MCP clients:
- Authorization code + PKCE
- Client credentials
- Device authorization grant
- Refresh tokens for supported grants
- OAuth 2.1-style stricter behavior inside the shared OAuth implementation:
  - S256 PKCE only
  - implicit grant rejected
  - resource parameter required for auth-code flows
  - issuer and audience semantics preserved on issued tokens

## Not Supported Yet

This server does not aim to cover all OAuth behavior in the wild. Not supported yet:
- Implicit grant
- Resource Owner Password Credentials
- JWT bearer grant
- Token exchange
- CIBA
- PAR, JAR, JARM
- DPoP
- mTLS or other sender-constrained tokens
- `private_key_jwt` client authentication
- Token introspection and revocation endpoints
- OIDC features such as ID tokens and userinfo
- Vendor-specific OAuth extensions

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

## Usage Notes

- Use `/mcp/oauth` when you want clients to exercise OAuth discovery, registration, token acquisition, and bearer-token access to the MCP resource.
- Use `/mcp/bearer-token` when you want a simpler non-OAuth bearer test case.
- OAuth access tokens and static bearer tokens both use the `Authorization: Bearer` header, but they are validated differently and are not interchangeable.

## Flow Examples

### Authorization code + PKCE

1. Fetch `/.well-known/oauth-protected-resource`
2. Fetch the advertised authorization server metadata
3. Register or use a public client
4. Call `/oauth/authorize` with `resource=http://<host>/mcp/oauth`
5. Exchange the returned code at `/oauth/token`
6. Call `/mcp/oauth` with the returned bearer token

### Client credentials

1. Register or use a confidential client
2. Request a token from `/oauth/token` with `grant_type=client_credentials`
3. Call `/mcp/oauth` with the returned bearer token

### Device flow

1. Call `/oauth/device/authorize`
2. Approve the user code via `/oauth/device/verify`
3. Exchange the device code at `/oauth/token`
4. Call `/mcp/oauth` with the returned bearer token

### Static bearer

1. Use the configured static token `test-bearer-token`, or mint one at `/test-auth/bearer-token/mint`
2. Call `/mcp/bearer-token` with the returned bearer token

## More Detail

See [docs/auth-schemes.md](docs/auth-schemes.md) for a more detailed walkthrough of the supported auth surfaces.
