"""Standalone client for exercising each auth scheme against a live server."""

from __future__ import annotations

import argparse
from dataclasses import dataclass

import httpx

from tests.flow_helpers import (
    bearer_headers,
    code_challenge,
    jsonrpc_payload,
    redirect_query,
)

SCHEMES = (
    "bearer-token",
    "oauth-v2-3l",
    "oauth-v2-2l",
    "oauth-v21",
    "dynamic-registration",
)


@dataclass(frozen=True, slots=True)
class SchemeResult:
    """Human-readable result for one live auth scheme check."""

    scheme: str
    detail: str


def _path_from_url(url: str, base_url: str) -> str:
    if url.startswith(base_url):
        return url.removeprefix(base_url)
    return url


def _assert_status(response: httpx.Response, expected: int) -> None:
    if response.status_code != expected:
        raise AssertionError(
            f"{response.request.method} {response.request.url} returned "
            f"{response.status_code}, expected {expected}: {response.text}"
        )


def run_bearer_token(client: httpx.Client) -> SchemeResult:
    discovery = client.get("/.well-known/oauth-protected-resource")
    _assert_status(discovery, 200)

    initialize = client.post(
        "/mcp/bearer-token",
        headers=bearer_headers(),
        json=jsonrpc_payload(request_id="live-bearer-init", method="initialize"),
    )
    _assert_status(initialize, 200)
    return SchemeResult("bearer-token", "discovery + initialize succeeded")


def run_oauth_v2_3l(client: httpx.Client, *, base_url: str) -> SchemeResult:
    metadata = client.get("/.well-known/oauth-authorization-server")
    _assert_status(metadata, 200)
    registration = client.post(
        _path_from_url(metadata.json()["registration_endpoint"], base_url),
        json={
            "client_name": "Phase 10 Live Browser Client",
            "redirect_uris": ["https://client.example/live/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )
    _assert_status(registration, 201)
    verifier = "phase-10-live-oauth-v2-verifier"

    authorize = client.get(
        _path_from_url(metadata.json()["authorization_endpoint"], base_url),
        params={
            "response_type": "code",
            "client_id": registration.json()["client_id"],
            "redirect_uri": "https://client.example/live/callback",
            "scope": "mcp:read",
            "state": "phase-10-live-oauth-v2-state",
            "code_challenge": code_challenge(verifier),
            "code_challenge_method": "S256",
            "auto_approve": "true",
        },
        follow_redirects=False,
    )
    _assert_status(authorize, 302)
    authorization_code = redirect_query(authorize.headers["location"])["code"][0]

    token = client.post(
        _path_from_url(metadata.json()["token_endpoint"], base_url),
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/live/callback",
            "client_id": registration.json()["client_id"],
            "code_verifier": verifier,
        },
    )
    _assert_status(token, 200)

    initialize = client.post(
        "/mcp/oauth-v2-auth-code",
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
        json=jsonrpc_payload(request_id="live-oauth-v2-init", method="initialize"),
    )
    _assert_status(initialize, 200)
    return SchemeResult("oauth-v2-3l", "discover/register/authorize/token/access succeeded")


def run_oauth_v2_2l(client: httpx.Client) -> SchemeResult:
    registration = client.post(
        "/oauth/register",
        json={
            "client_name": "Phase 10 Live Service Client",
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
            "scope": "mcp:write",
        },
    )
    _assert_status(registration, 201)

    token = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": registration.json()["client_id"],
            "client_secret": registration.json()["client_secret"],
            "scope": "mcp:write",
        },
    )
    _assert_status(token, 200)

    initialize = client.post(
        "/mcp/oauth-v2-client-creds",
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
        json=jsonrpc_payload(request_id="live-client-creds-init", method="initialize"),
    )
    _assert_status(initialize, 200)
    return SchemeResult("oauth-v2-2l", "register/token/access succeeded")


def run_oauth_v21(client: httpx.Client, *, base_url: str) -> SchemeResult:
    resource_metadata = client.get(
        "/.well-known/oauth-protected-resource",
        params={"resource": f"{base_url}/mcp/oauth-v21"},
    )
    _assert_status(resource_metadata, 200)
    auth_server = client.get(
        _path_from_url(resource_metadata.json()["authorization_servers"][0], base_url)
    )
    _assert_status(auth_server, 200)
    registration = client.post(
        _path_from_url(auth_server.json()["registration_endpoint"], base_url),
        json={
            "client_name": "Phase 10 Live OAuth 2.1 Client",
            "redirect_uris": ["https://client.example/live/oauth-v21/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )
    _assert_status(registration, 201)
    verifier = "phase-10-live-oauth-v21-verifier"

    authorize = client.get(
        _path_from_url(auth_server.json()["authorization_endpoint"], base_url),
        params={
            "response_type": "code",
            "client_id": registration.json()["client_id"],
            "redirect_uri": "https://client.example/live/oauth-v21/callback",
            "scope": "mcp:read",
            "state": "phase-10-live-oauth-v21-state",
            "resource": f"{base_url}/mcp/oauth-v21",
            "code_challenge": code_challenge(verifier),
            "code_challenge_method": "S256",
            "auto_approve": "true",
        },
        follow_redirects=False,
    )
    _assert_status(authorize, 302)
    authorization_code = redirect_query(authorize.headers["location"])["code"][0]

    token = client.post(
        _path_from_url(auth_server.json()["token_endpoint"], base_url),
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://client.example/live/oauth-v21/callback",
            "client_id": registration.json()["client_id"],
            "code_verifier": verifier,
            "resource": f"{base_url}/mcp/oauth-v21",
        },
    )
    _assert_status(token, 200)

    initialize = client.post(
        "/mcp/oauth-v21",
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
        json=jsonrpc_payload(request_id="live-oauth-v21-init", method="initialize"),
    )
    _assert_status(initialize, 200)
    return SchemeResult("oauth-v21", "discover/register/authorize/token/access succeeded")


def run_dynamic_registration(client: httpx.Client) -> SchemeResult:
    public_client = client.post(
        "/oauth/register",
        json={
            "client_name": "Phase 10 Live Public Client",
            "redirect_uris": ["https://client.example/live/public/callback"],
        },
    )
    _assert_status(public_client, 201)
    confidential_client = client.post(
        "/oauth/register",
        json={
            "client_name": "Phase 10 Live Confidential Client",
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    _assert_status(confidential_client, 201)
    return SchemeResult("dynamic-registration", "public + confidential registration succeeded")


def run_scheme(scheme: str, client: httpx.Client, *, base_url: str) -> SchemeResult:
    if scheme == "bearer-token":
        return run_bearer_token(client)
    if scheme == "oauth-v2-3l":
        return run_oauth_v2_3l(client, base_url=base_url)
    if scheme == "oauth-v2-2l":
        return run_oauth_v2_2l(client)
    if scheme == "oauth-v21":
        return run_oauth_v21(client, base_url=base_url)
    if scheme == "dynamic-registration":
        return run_dynamic_registration(client)
    raise ValueError(f"Unsupported scheme: {scheme}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8765",
        help="Base URL for the running mcp-auth-test-server instance.",
    )
    parser.add_argument(
        "--scheme",
        default="all",
        choices=("all", *SCHEMES),
        help="Which scheme to exercise.",
    )
    args = parser.parse_args()

    schemes = SCHEMES if args.scheme == "all" else (args.scheme,)
    with httpx.Client(base_url=args.base_url, timeout=10.0) as client:
        for scheme in schemes:
            result = run_scheme(scheme, client, base_url=args.base_url.rstrip("/"))
            print(f"PASS {result.scheme}: {result.detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
