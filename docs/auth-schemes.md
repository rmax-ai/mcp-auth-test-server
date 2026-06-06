# MCP Auth Test Server — Auth Schemes Reference

## Static Bearer Token

**Protected resource:** `/mcp/bearer-token`  
**Mint helper:** `/test-auth/bearer-token/mint`  
**Spec:** RFC 6750

This surface accepts:
- the configured static bearer token
- short-lived prefixed tokens minted by the test helper endpoint

It does not participate in OAuth discovery or token issuance.

## Unified OAuth Protected Resource

**Protected resource:** `/mcp/oauth`

This surface accepts OAuth-issued bearer tokens obtained from the shared authorization server. The server supports:
- authorization code + PKCE
- client credentials
- device authorization grant
- refresh tokens for supported grants

All OAuth-issued tokens target the same MCP resource and carry:
- `aud = http://<host>/mcp/oauth`
- `iss = http://<host>`

## OAuth Authorization Server

**Endpoints:**
- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-authorization-server`
- `/oauth/authorize`
- `/oauth/token`
- `/oauth/device/authorize`
- `/oauth/device/verify`
- `/oauth/device/verify/consent`
- `/oauth/register`

### Authorization Code + PKCE

1. Client requests `/mcp/oauth` and discovers protected resource metadata.
2. Client fetches authorization server metadata.
3. Client registers or uses a public client.
4. Client opens `/oauth/authorize` with:
   - `response_type=code`
   - `resource=http://<host>/mcp/oauth`
   - `code_challenge` and `code_challenge_method=S256`
5. User approves access.
6. Client exchanges the code at `/oauth/token`.
7. Client calls `/mcp/oauth` with the returned bearer token.

### Client Credentials

1. Client registers or uses a confidential client.
2. Client calls `/oauth/token` with `grant_type=client_credentials`.
3. Client calls `/mcp/oauth` with the returned bearer token.

### Device Authorization Grant

1. Client calls `/oauth/device/authorize`.
2. User completes verification via `/oauth/device/verify`.
3. Client exchanges the device code at `/oauth/token`.
4. Client calls `/mcp/oauth` with the returned bearer token.

## OAuth 2.1-Style Behavior

The shared OAuth surface keeps stricter behavior commonly associated with OAuth 2.1:
- PKCE `S256` only
- implicit grant rejected
- resource parameter required for auth-code flows
- issuer returned on authorization redirects
- issuer and audience preserved on issued and refreshed tokens

## Not Supported Yet

- Implicit grant
- Resource Owner Password Credentials
- JWT bearer grant
- Token exchange
- CIBA
- PAR, JAR, JARM
- DPoP
- mTLS or other sender-constrained tokens
- `private_key_jwt` client auth
- Token introspection and revocation
- OIDC features such as ID tokens and userinfo
- Vendor-specific OAuth extensions
