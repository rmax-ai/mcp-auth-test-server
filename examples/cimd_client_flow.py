# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx"]
# ///

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx


def build_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


class CimdHandler(BaseHTTPRequestHandler):
    metadata_document: dict[str, object] = {}
    code: str | None = None
    state: str | None = None
    event = threading.Event()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/cimd-metadata.json":
            body = json.dumps(CimdHandler.metadata_document, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/callback":
            params = parse_qs(parsed.query)
            CimdHandler.code = params.get("code", [None])[0]
            CimdHandler.state = params.get("state", [None])[0]
            CimdHandler.event.set()

            body = (
                b"<html><body><h1>Authorization received</h1>"
                b"<p>You can return to the terminal.</p></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


def wait_for_callback(server: ThreadingHTTPServer) -> tuple[str, str | None]:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print("Waiting for browser redirect to the local CIMD callback ...")
    CimdHandler.event.wait()
    server.shutdown()
    server.server_close()

    if CimdHandler.code is None:
        raise RuntimeError("authorization callback completed without a code")
    return CimdHandler.code, CimdHandler.state


def pretty_print(title: str, payload: object) -> None:
    print(f"\n== {title} ==")
    print(json.dumps(payload, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description="Demonstrate the CIMD auth-code + PKCE flow.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--dev-mode", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    resource = f"{base_url}/mcp/oauth"

    local_server = ThreadingHTTPServer(("127.0.0.1", 0), CimdHandler)
    local_port = local_server.server_address[1]
    client_id = f"http://127.0.0.1:{local_port}/cimd-metadata.json"
    redirect_uri = f"http://127.0.0.1:{local_port}/callback"
    CimdHandler.metadata_document = {
        "client_id": client_id,
        "client_name": "Example CIMD Client",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "mcp:tools:list mcp:tools:echo",
    }
    CimdHandler.code = None
    CimdHandler.state = None
    CimdHandler.event.clear()

    with httpx.Client(timeout=10.0) as client:
        try:
            metadata = client.get(f"{base_url}/.well-known/oauth-authorization-server")
            metadata.raise_for_status()
            auth_server_metadata = metadata.json()
            pretty_print("Authorization Server Metadata", auth_server_metadata)

            code_verifier = secrets.token_urlsafe(48)
            code_challenge = build_code_challenge(code_verifier)
            state = secrets.token_urlsafe(12)
            authorization_params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": "mcp:tools:list mcp:tools:echo",
                "state": state,
                "resource": resource,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }

            authorization_url = (
                f"{auth_server_metadata['authorization_endpoint']}?"
                f"{urlencode(authorization_params)}"
            )
            print("\n== CIMD Metadata Document ==")
            print(client_id)
            pretty_print("Served CIMD Metadata", CimdHandler.metadata_document)
            print("\n== Authorization URL ==")
            print(authorization_url)
            print(
                "\nOpen the URL in your browser, approve access, and wait for the callback. "
                f"Server dev mode expected: {args.dev_mode}."
            )

            authorization_code, returned_state = wait_for_callback(local_server)
            print("\n== Authorization Callback ==")
            print(f"code={authorization_code}")
            print(f"state={returned_state}")

            token = client.post(
                auth_server_metadata["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": authorization_code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "code_verifier": code_verifier,
                    "resource": resource,
                },
            )
            token.raise_for_status()
            token_response = token.json()
            pretty_print("Token Response", token_response)

            mcp_response = client.post(
                resource,
                headers={"Authorization": f"Bearer {token_response['access_token']}"},
                json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
            )
            mcp_response.raise_for_status()
            pretty_print("Protected MCP Response", mcp_response.json())
        except httpx.HTTPError as exc:
            local_server.server_close()
            print(f"HTTP error: {exc}")
            return 1
        except KeyError as exc:
            local_server.server_close()
            print(f"Missing expected field in server response: {exc}")
            return 1
        except RuntimeError as exc:
            print(f"Flow error: {exc}")
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
