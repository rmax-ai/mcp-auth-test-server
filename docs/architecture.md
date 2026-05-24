# Architecture

## Overview

This repo has two main deliverables:

- `mcp_auth_test_server`: a FastAPI application exposing MCP endpoints with
  distinct auth behavior
- `mcp-auth`: a standalone CLI that exercises generic MCP auth flows from the
  client side

The design goal is clarity over convenience: different auth surfaces stay
separate so client implementations can be tested without hidden coupling.

## Server shape

Key Python packages:

- `src/mcp_auth_test_server/app.py`
- `src/mcp_auth_test_server/mcp/`
- `src/mcp_auth_test_server/auth/`
- `src/mcp_auth_test_server/discovery/`

### MCP protected resources

- `/mcp/bearer-token`
  - static bearer-token surface
  - no OAuth discovery or token issuance
- `/mcp/oauth`
  - unified OAuth-protected MCP surface
  - accepts OAuth-issued bearer tokens from supported grants

### Shared OAuth authorization server

The shared OAuth implementation provides:

- protected-resource discovery
- authorization-server metadata
- authorization code + PKCE
- client credentials
- device authorization grant
- refresh tokens for supported profiles
- dynamic client registration

## State model

The server uses in-memory state only:

- authorization codes
- device codes
- registered clients
- access tokens
- refresh tokens

This keeps the test fixture simple and resettable between runs and tests.

## CLI shape

Key package:

- `src/mcp_auth_cli/`

Important submodules:

- `auth/discovery.py`
- `auth/token_manager.py`
- `auth/auth_code.py`
- `auth/device_code.py`
- `auth/client_credentials.py`
- `profiles/store.py`
- `cli/commands.py`

### CLI model

The CLI is resource-centric:

1. discover the protected resource
2. discover one or more authorization servers
3. choose or run an auth flow
4. persist a local profile
5. refresh or reacquire tokens as needed before MCP calls

### Profile behavior

Profiles store:

- the resource URL
- selected auth mode
- token endpoint and discovery metadata
- tokens and expiry
- client registration data where applicable

The CLI automatically:

- refreshes auth-code and device tokens when refresh tokens are available
- reacquires client-credentials tokens when expired
- refuses to auto-refresh manual bearer profiles

## Docs website

`docs/site/` is a separate SvelteKit + mdsvex project used to publish project
documentation to GitHub Pages.

It is intentionally isolated from the Python package so:

- Node dependencies do not affect the Python environment
- GitHub Pages deployment stays separate from server runtime concerns
- markdown-heavy content can be authored as mdsvex pages
