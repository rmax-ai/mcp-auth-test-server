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
    "oauth-auth-code",
    "oauth-client-creds",
    "oauth-device-flow",
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
    initialize = client.post(
        "/mcp/bearer-token",
        headers=bearer_headers(),
        json=jsonrpc_payload(request_id="live-bearer-init", method="initialize"),
    )
    _assert_status(initialize, 200)
    return SchemeResult("bearer-token", "initialize succeeded")


def run_oauth_auth_code(client: httpx.Client, *, base_url: str) -> SchemeResult:
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
    verifier = "phase-10-live-oauth-verifier"

    authorize = client.get(
        _path_from_url(metadata.json()["authorization_endpoint"], base_url),
        params={
            "response_type": "code",
            "client_id": registration.json()["client_id"],
            "redirect_uri": "https://client.example/live/callback",
            "scope": "mcp:read",
            "state": "phase-10-live-oauth-state",
            "resource": f"{base_url}/mcp/oauth",
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
            "resource": f"{base_url}/mcp/oauth",
        },
    )
    _assert_status(token, 200)

    initialize = client.post(
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
        json=jsonrpc_payload(request_id="live-oauth-init", method="initialize"),
    )
    _assert_status(initialize, 200)
    return SchemeResult("oauth-auth-code", "discover/register/authorize/token/access succeeded")


def run_oauth_client_creds(client: httpx.Client) -> SchemeResult:
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
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
        json=jsonrpc_payload(request_id="live-client-creds-init", method="initialize"),
    )
    _assert_status(initialize, 200)
    return SchemeResult("oauth-client-creds", "register/token/access succeeded")


def run_oauth_device_flow(client: httpx.Client) -> SchemeResult:
    authorize = client.post(
        "/oauth/device/authorize",
        data={"client_id": "phase-11-device-client"},
    )
    _assert_status(authorize, 200)

    client.post(
        "/oauth/device/verify/consent",
        data={"user_code": authorize.json()["user_code"], "decision": "approve"},
    )
    token = client.post(
        "/oauth/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": "phase-11-device-client",
            "device_code": authorize.json()["device_code"],
        },
    )
    _assert_status(token, 200)

    initialize = client.post(
        "/mcp/oauth",
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
        json=jsonrpc_payload(request_id="live-device-init", method="initialize"),
    )
    _assert_status(initialize, 200)
    return SchemeResult("oauth-device-flow", "device authorize/token/access succeeded")


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
    if scheme == "oauth-auth-code":
        return run_oauth_auth_code(client, base_url=base_url)
    if scheme == "oauth-client-creds":
        return run_oauth_client_creds(client)
    if scheme == "oauth-device-flow":
        return run_oauth_device_flow(client)
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
    with httpx.Client(base_url=args.base_url, follow_redirects=False, timeout=10.0) as client:
        for scheme in schemes:
            result = run_scheme(scheme, client, base_url=args.base_url.rstrip("/"))
            print(f"[ok] {result.scheme}: {result.detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
