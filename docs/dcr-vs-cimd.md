# DCR vs CIMD

This test server supports two client onboarding models for OAuth-protected MCP
resources:

- **Dynamic Client Registration (DCR)** using RFC 7591 at `/oauth/register`
- **Client ID Metadata Documents (CIMD)** using a URL-valued `client_id` that
  points at hosted client metadata

Both models can drive the same authorization-code + PKCE flow, but they make
different tradeoffs around operational state, security, and local development.

## Overview

With DCR, the client sends metadata directly to the authorization server and
receives a server-managed `client_id` back. The server stores that record and
uses it for later authorization and token requests.

With CIMD, the client’s `client_id` is itself the metadata document URL. The
authorization server fetches the document on demand, validates it, and then
uses the resolved metadata as if the client had been registered already.

## Comparison

| Concern | DCR | CIMD |
| --- | --- | --- |
| Registration model | Client `POST`s metadata to `/oauth/register` | `client_id` points at a metadata document URL |
| Server state | Persistent in-memory registration record | Resolver cache plus optional in-memory registration after resolution |
| Operational complexity | Straightforward server-owned state | Requires URL fetching, DNS checks, caching, and SSRF controls |
| Security risks | Metadata validation and client secret handling | SSRF, metadata tampering, redirect URI validation, and fetch timeouts |
| MCP fit | Useful for flexible test harnesses and ephemeral clients | Useful when the client identity should be self-describing |
| Enterprise governance fit | Easier to approve and inventory centrally | Better when metadata publishing is governed outside the auth server |
| Local development fit | Simple and reliable for localhost testing | Works well only when development-mode HTTP/localhost exceptions are allowed |

## Server-side implementation

The DCR path is unchanged in principle: `/oauth/register` validates the posted
metadata, persists a `ClientRecord`, and returns an RFC 7591-style response.
The server now also records trace events for registration start, validation
failures, and successful registrations.

The CIMD path is split into two layers:

1. `auth/cimd_resolver.py` validates the metadata URL, blocks private and
   link-local targets, fetches the JSON document with redirect and size limits,
   validates the returned metadata, and caches successful resolutions for 300
   seconds.
2. `auth/cimd_integration.py` turns a URL-based `client_id` into a normal
   `ClientRecord` in the shared token store so the existing authorization and
   token validation paths can keep using the same client lookup logic.

The debug router also exposes `/debug/traces`, which returns the structured
trace logger output for DCR and CIMD activity.

## Client-side flow walkthrough

### DCR flow

1. Discover the authorization server metadata.
2. Register a public client at `/oauth/register`.
3. Generate a PKCE verifier and `S256` challenge.
4. Open the authorization URL in a browser.
5. Receive the authorization code on the local callback listener.
6. Exchange the code at `/oauth/token`.
7. Call `/mcp/oauth` with the returned bearer token.

The repository example is [`examples/dcr_client_flow.py`](../examples/dcr_client_flow.py).

### CIMD flow

1. Start a local server that serves `cimd-metadata.json`.
2. Use that metadata URL as the `client_id`.
3. Discover the authorization server metadata.
4. Generate PKCE parameters.
5. Open the authorization URL in a browser.
6. Let the authorization server fetch and validate the metadata document.
7. Receive the authorization code on the local callback listener.
8. Exchange the code at `/oauth/token`.
9. Call `/mcp/oauth` with the returned bearer token.

The repository example is [`examples/cimd_client_flow.py`](../examples/cimd_client_flow.py).

## Security notes

- **SSRF protection matters for CIMD.** The resolver only allows HTTPS by
  default, resolves DNS before fetching, rejects private and link-local
  addresses, blocks `169.254.169.254`, enforces a 5-second timeout, and caps
  documents at 64 KB.
- **Development mode relaxes only what local demos need.** HTTP and localhost
  redirect URIs are allowed there so local examples can run, but those
  exceptions should not be enabled in production deployments.
- **Redirect URI validation remains mandatory.** Even after CIMD resolution,
  authorization requests must still use a redirect URI present in the metadata
  document.
- **PKCE remains required.** The shared auth-code flow still requires
  `code_challenge_method=S256`, and token exchange still depends on the correct
  `code_verifier`.

## Troubleshooting

### `invalid_client` during `/oauth/authorize`

The server could not find a registered DCR client and could not resolve the
CIMD document. Check the `client_id`, verify the metadata URL is reachable, and
inspect `/debug/traces` for `cimd_fetch_error` or `cimd_validation_error`.

### `redirect_uri is not registered for this client`

The callback URI in the authorization request does not exactly match one of the
declared `redirect_uris`. Check the stored DCR metadata or the hosted CIMD
document.

### `client metadata URLs must use https`

The resolver is running in production mode. Use an HTTPS metadata URL, or in
local-only testing enable the development-mode exceptions used by the example
flow.

### `client metadata document exceeds 64KB limit`

The CIMD document is too large for the resolver’s fetch policy. Trim the
metadata to the minimum fields needed for the auth flow.

### `code_verifier does not match code_challenge`

The token exchange did not use the original PKCE verifier. Regenerate the
authorization URL and make sure the same verifier is sent to `/oauth/token`.
