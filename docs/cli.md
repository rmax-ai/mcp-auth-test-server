# `mcp-auth` CLI Guide

The standalone `mcp-auth` CLI is a server-agnostic MCP auth client. It
discovers protected-resource metadata, selects or runs an auth flow, stores
reusable local profiles, and keeps tokens current for later MCP calls.

## Install

```bash
uv sync --extra dev
uv run mcp-auth --help
```

## Core commands

```bash
uv run mcp-auth discover <resource-url>
uv run mcp-auth login <resource-url>
uv run mcp-auth call <resource-url> initialize
uv run mcp-auth profile list
uv run mcp-auth logout <resource-url>
```

## Supported auth modes

- `bearer`
- `auth-code`
- `device`
- `client-creds`

If `--auth-mode` is omitted, `login` uses discovery and existing profile state
to choose the best available flow in this order:

1. an existing refreshable profile
2. stored or supplied client credentials
3. device flow
4. authorization code flow
5. manual bearer token

## Common flows

### Static bearer

```bash
uv run mcp-auth login \
  http://127.0.0.1:8765/mcp/bearer-token \
  --auth-mode bearer \
  --bearer-token test-bearer-token

uv run mcp-auth call http://127.0.0.1:8765/mcp/bearer-token initialize
```

### Authorization code + PKCE

```bash
uv run mcp-auth login \
  http://127.0.0.1:8765/mcp/oauth \
  --auth-mode auth-code \
  --register
```

The CLI starts a localhost callback listener on a separate port, prints the
authorization URL, and waits for the browser redirect in the background.

### Device flow

```bash
uv run mcp-auth login \
  http://127.0.0.1:8765/mcp/oauth \
  --auth-mode device \
  --register
```

The CLI prints `verification_uri` and `user_code`, then polls the token
endpoint until the device is approved or the flow fails.

### Client credentials

```bash
uv run mcp-auth login \
  http://127.0.0.1:8765/mcp/oauth \
  --auth-mode client-creds \
  --register \
  --scope mcp:write
```

## Profiles and token maintenance

- Profiles are stored locally with restrictive file permissions.
- Auth-code and device profiles use refresh tokens when available.
- Client-credentials profiles reacquire access tokens when expired.
- Manual bearer profiles are never auto-refreshed.

Useful inspection commands:

```bash
uv run mcp-auth profile list
uv run mcp-auth profile show --resource-url http://127.0.0.1:8765/mcp/oauth
```

## Troubleshooting

- Use `--verbose` on `discover`, `login`, or `call` to print protocol details.
- If a bearer token changes or expires, rerun `login`.
- If auth-code login cannot receive a localhost callback, supply a different
  loopback port with `--listen-port`.
