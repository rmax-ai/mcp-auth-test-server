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
# Install dependencies
uv sync --dev

# Run
uv run uvicorn mcp_auth_test_server.app:app --reload --port 8765

# Test
uv run pytest tests/ -v
```

## Docs site

The repo includes a static docs website under `docs/site`, built with
SvelteKit, `adapter-static`, and mdsvex. It is deployed to GitHub Pages by
`.github/workflows/deploy-docs.yml`.

Local docs-site commands:

```bash
cd docs/site
npm install
npm run dev
npm run check
npm run build
```

## Standalone CLI

This repo now includes a standalone `mcp-auth` CLI for exercising generic MCP
auth flows against arbitrary protected resources. The CLI is resource-centric
rather than server-specific: it discovers auth metadata, helps complete login,
stores reusable local profiles, and keeps tokens current for later MCP calls.

### Install the CLI

```bash
uv sync --dev
uv run mcp-auth --help
```

### Core commands

```bash
# Discover advertised auth capabilities for a protected resource
uv run mcp-auth discover http://127.0.0.1:8765/mcp/oauth

# Login using the best available flow, or force one explicitly
uv run mcp-auth login http://127.0.0.1:8765/mcp/oauth
uv run mcp-auth login http://127.0.0.1:8765/mcp/oauth --auth-mode device
uv run mcp-auth login http://127.0.0.1:8765/mcp/oauth --auth-mode auth-code --register
uv run mcp-auth login http://127.0.0.1:8765/mcp/bearer-token --auth-mode bearer

# Call MCP JSON-RPC methods
uv run mcp-auth call http://127.0.0.1:8765/mcp/oauth initialize
uv run mcp-auth call http://127.0.0.1:8765/mcp/oauth tools/list
uv run mcp-auth call http://127.0.0.1:8765/mcp/oauth tools/call --tool-name ping
uv run mcp-auth call \
  http://127.0.0.1:8765/mcp/oauth \
  tools/call \
  --tool-name echo \
  --tool-arguments '{"message":"hello","uppercase":true}'

# Inspect or switch saved profiles
uv run mcp-auth profile list
uv run mcp-auth profile show --resource-url http://127.0.0.1:8765/mcp/oauth

# Remove the active profile for a resource
uv run mcp-auth logout http://127.0.0.1:8765/mcp/oauth
```

### Auth modes

The CLI supports four auth modes:
- `bearer` for user-supplied opaque bearer tokens
- `auth-code` for authorization code + PKCE
- `device` for device authorization grant
- `client-creds` for confidential client credentials

For auth-code logins, the CLI defaults to a localhost callback listener on a
separate port, prints the authorization URL, and waits for the browser redirect
in the background. Use `--listen-port` to force a specific callback port.

If `--auth-mode` is omitted, `mcp-auth login` discovers the protected resource
and chooses the best available option using this order:
- an existing refreshable profile
- stored or supplied client credentials
- device flow
- authorization code flow
- manual bearer token

### Profiles and token refresh

- Profiles are stored locally with restrictive file permissions and reused on
  later commands.
- `mcp-auth call` automatically ensures there is a valid access token before
  contacting the MCP endpoint.
- For auth-code and device profiles, the CLI uses a stored refresh token when
  one is available.
- For client-credentials profiles, the CLI requests a fresh access token when
  the current one expires.
- Manual bearer profiles are never refreshed automatically; re-run `login` if a
  bearer token changes or expires.
- Use `--verbose` on `discover`, `login`, or `call` to print raw endpoint and
  protocol details.

### End-to-end CLI flow tests

Start the server in one terminal:

```bash
uv sync --dev
uv run uvicorn mcp_auth_test_server.app:app --reload --port 8765
```

Run the following sequences from another terminal.

#### Static bearer

```bash
uv run mcp-auth login \
  http://127.0.0.1:8765/mcp/bearer-token \
  --auth-mode bearer \
  --bearer-token test-bearer-token

uv run mcp-auth call http://127.0.0.1:8765/mcp/bearer-token initialize
uv run mcp-auth call http://127.0.0.1:8765/mcp/bearer-token tools/list
uv run mcp-auth call \
  http://127.0.0.1:8765/mcp/bearer-token \
  tools/call \
  --tool-name ping
```

#### Authorization code + PKCE

```bash
uv run mcp-auth discover http://127.0.0.1:8765/mcp/oauth

uv run mcp-auth login \
  http://127.0.0.1:8765/mcp/oauth \
  --auth-mode auth-code \
  --register
```

The login command starts a localhost callback listener, prints an authorization
URL, and waits for the browser redirect in the background. Open the URL and
approve consent.

```bash
uv run mcp-auth call http://127.0.0.1:8765/mcp/oauth initialize
uv run mcp-auth call http://127.0.0.1:8765/mcp/oauth tools/list
uv run mcp-auth call \
  http://127.0.0.1:8765/mcp/oauth \
  tools/call \
  --tool-name echo \
  --tool-arguments '{"message":"hello","uppercase":true}'
```

#### Device flow

```bash
uv run mcp-auth login \
  http://127.0.0.1:8765/mcp/oauth \
  --auth-mode device \
  --register
```

The CLI prints `verification_uri` and `user_code`. Visit the URI, approve the
code, then let the CLI finish polling.

```bash
uv run mcp-auth call http://127.0.0.1:8765/mcp/oauth initialize
uv run mcp-auth call http://127.0.0.1:8765/mcp/oauth tools/list
uv run mcp-auth call \
  http://127.0.0.1:8765/mcp/oauth \
  tools/call \
  --tool-name ping
```

#### Client credentials

```bash
uv run mcp-auth login \
  http://127.0.0.1:8765/mcp/oauth \
  --auth-mode client-creds \
  --register \
  --scope mcp:write

uv run mcp-auth call http://127.0.0.1:8765/mcp/oauth initialize
uv run mcp-auth call http://127.0.0.1:8765/mcp/oauth tools/list
uv run mcp-auth call \
  http://127.0.0.1:8765/mcp/oauth \
  tools/call \
  --tool-name ping
```

Useful follow-up commands after any flow:

```bash
uv run mcp-auth profile list
uv run mcp-auth profile show --resource-url http://127.0.0.1:8765/mcp/oauth
uv run mcp-auth logout http://127.0.0.1:8765/mcp/oauth
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
