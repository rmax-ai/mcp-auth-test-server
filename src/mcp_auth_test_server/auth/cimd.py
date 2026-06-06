"""CIMD (Client Identification and Metadata Distribution) helpers.

The MCP specification defines a static client model where clients are
pre-registered by the authorization server operator rather than
dynamically registered via RFC 7591.

This test server intentionally supports both models:
- **CIMD** — static fixture clients seeded in token_store.py
  (dev-public-client, dev-confidential-client, dev-admin-client).
- **DCR** — RFC 7591 dynamic registration at /oauth/register (kept
  as a harness convenience for test flexibility).

The CIMD model aligns with the spec's expectation that test harnesses
ship with known client identities, enabling predictable token-issuance
flows without a registration step.
"""

from __future__ import annotations

from mcp_auth_test_server.auth.token_store import oauth_token_store

# Well-known fixture client IDs for CIMD-style resolution
CIMD_FIXTURE_CLIENTS = {
    "dev-public-client",
    "dev-confidential-client",
    "dev-admin-client",
}

# Scope-to-profile mapping for CIMD fixture resolution
CLIENT_PROFILE_SCOPES: dict[str, str] = {
    "dev-public-client": "public",
    "dev-confidential-client": "confidential",
    "dev-admin-client": "admin",
}


def resolve_fixture_client(client_id: str) -> bool:
    """Return True when the client_id is a known CIMD fixture client."""
    return client_id in CIMD_FIXTURE_CLIENTS


def get_client_profile(client_id: str) -> str | None:
    """Return the semantic profile for a CIMD fixture client, or None."""
    return CLIENT_PROFILE_SCOPES.get(client_id)
