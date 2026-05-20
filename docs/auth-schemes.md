# MCP Auth Test Server — Auth Schemes Reference

## No Auth

**Endpoint:** `/mcp/no-auth`
**Spec:** None

No authentication required. All requests accepted.

## Bearer Token

**Endpoint:** `/mcp/bearer-token`
**Spec:** RFC 6750

Static bearer token via `Authorization: Bearer <token>` header. Returns 401 with `WWW-Authenticate` on missing/invalid token.

## OAuth 1.0a (Legacy)

**Endpoint:** `/mcp/oauth-v1`
**Spec:** RFC 5849

HMAC-SHA1 signature-based authentication. Consumer key/secret pair verified against request signature.

## OAuth 2.0 Authorization Code + PKCE (3-legged)

**Endpoints:**
- `/mcp/oauth-v2-auth-code` — protected MCP endpoint
- `/.well-known/oauth-authorization-server` — server metadata
- `/.well-known/oauth-protected-resource` — resource metadata
- `/oauth/authorize` — authorization endpoint
- `/oauth/token` — token endpoint

**Flow:**
1. Client requests MCP → 401 + WWW-Authenticate with resource_metadata
2. Client fetches `/.well-known/oauth-protected-resource` → gets AS URL
3. Client fetches `/.well-known/oauth-authorization-server` → gets AS metadata
4. Client generates PKCE code_challenge
5. Client opens browser to `/authorize?response_type=code&...`
6. User authorizes → redirect with authorization code
7. Client exchanges code at `/token` with code_verifier
8. Client uses Bearer token on `/mcp/oauth-v2-auth-code`

## OAuth 2.0 Client Credentials (2-legged)

**Endpoint:** `/mcp/oauth-v2-client-creds`
**Spec:** RFC 6749 Section 4.4

Machine-to-machine flow. Client sends `grant_type=client_credentials` to `/token` with client_id/client_secret, receives access token.
Mock credentials:
- `client_id=phase-6-service-client`
- `client_secret=phase-6-service-secret`

## OAuth 2.1 Authorization Code + PKCE

**Endpoints:**
- `/mcp/oauth-v21` — protected MCP endpoint
- `/oauth-v21/authorize` — OAuth 2.1 authorization endpoint
- `/oauth-v21/token` — OAuth 2.1 token endpoint
- `/.well-known/oauth-protected-resource?resource=http://<host>/mcp/oauth-v21` — resource metadata
- `/.well-known/oauth-authorization-server?resource=http://<host>/mcp/oauth-v21` — AS metadata
**Spec:** OAuth 2.1 (draft)

OAuth 2.1 with all security requirements:
- S256 PKCE only (no `plain`)
- No implicit grant
- Resource parameter (RFC 8707) on authorize + token
- Audience validation on tokens
- `iss` parameter (RFC 9207) on authorization redirect, with `iss` echoed in mock token response

Mock client:
- `client_id=phase-7-public-client`

## Dynamic Client Registration

**Endpoint:** `/register`
**Spec:** RFC 7591

Client POSTs registration metadata to receive client_id (and optionally client_secret). Supports `token_endpoint_auth_method: none` for public clients.
