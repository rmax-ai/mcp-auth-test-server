"""OAuth authorization code + PKCE strategy."""

from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse
from uuid import uuid4

from mcp_auth_cli.errors import CliError
from mcp_auth_cli.models import AUTH_MODE_AUTH_CODE, AuthorizationServerMetadata, Profile


def login_with_authorization_code(
    client,
    *,
    ui,
    resource_url: str,
    auth_server: AuthorizationServerMetadata,
    scope: str | None,
    client_id: str | None,
    redirect_uri: str | None,
    register: bool,
    listen_port: int | None,
    open_browser: bool,
) -> Profile:
    if auth_server.authorization_endpoint is None or auth_server.token_endpoint is None:
        raise CliError("Authorization server metadata is missing required authorization endpoints.")

    callback_server = None
    resolved_redirect_uri = redirect_uri
    if resolved_redirect_uri is None:
        callback_server = _LoopbackCallbackServer.create(
            host="127.0.0.1",
            port=listen_port or 0,
            path="/callback",
        )
        callback_server.start()
        resolved_redirect_uri = callback_server.redirect_uri
    elif _is_loopback_redirect(resolved_redirect_uri):
        callback_server = _LoopbackCallbackServer.from_redirect_uri(resolved_redirect_uri)
        callback_server.start()
    elif not resolved_redirect_uri:
        raise CliError("Authorization code flow requires a redirect URI.")

    resolved_client_id = client_id
    registration_payload = None
    if register:
        if auth_server.registration_endpoint is None:
            raise CliError("This authorization server does not advertise dynamic registration.")
        registration_payload = _register_client(
            client,
            auth_server,
            resolved_redirect_uri,
            scope=scope,
        )
        resolved_client_id = registration_payload["client_id"]
        ui.step(f"Registered public client {resolved_client_id}")
    if not resolved_client_id:
        resolved_client_id = ui.prompt("Client ID")
    if not resolved_client_id:
        raise CliError("Authorization code flow requires a client_id.")

    state = secrets.token_urlsafe(12)
    code_verifier = secrets.token_urlsafe(48)
    code_challenge = _code_challenge(code_verifier)
    params = {
        "response_type": "code",
        "client_id": resolved_client_id,
        "redirect_uri": resolved_redirect_uri,
        "state": state,
        "resource": resource_url,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if scope:
        params["scope"] = scope
    authorization_url = f"{auth_server.authorization_endpoint}?{urlencode(params)}"

    redirect_result: str | None = None
    if callback_server is not None:
        ui.step(f"Listening for the authorization callback on {resolved_redirect_uri}")
    ui.step("Open the authorization URL in a browser")
    ui.info(authorization_url)
    if open_browser:
        webbrowser.open(authorization_url)

    if callback_server is not None:
        redirect_result = callback_server.wait_for_url(timeout=180)
    if redirect_result is None and callback_server is None:
        redirect_result = ui.prompt("Paste the final redirect URL")
    if callback_server is not None:
        callback_server.close()
    if redirect_result is None:
        raise CliError("Timed out waiting for the authorization callback.")

    query = parse_qs(urlparse(redirect_result).query, keep_blank_values=True)
    if query.get("state", [None])[0] != state:
        raise CliError("Authorization response state did not match the original request.")
    redirect_issuer = query.get("iss", [None])[0]
    if redirect_issuer and auth_server.issuer and redirect_issuer != auth_server.issuer:
        raise CliError("Authorization response issuer did not match discovered metadata.")
    error_code = query.get("error", [None])[0]
    if error_code:
        raise CliError(f"Authorization failed with error: {error_code}")
    code = query.get("code", [None])[0]
    if not code:
        raise CliError("Authorization response did not include a code.")

    token_response = client.post(
        auth_server.token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": resolved_redirect_uri,
            "client_id": resolved_client_id,
            "code_verifier": code_verifier,
            "resource": resource_url,
        },
    )
    if token_response.status_code >= 400:
        raise CliError(
            f"Authorization code token exchange failed: HTTP {token_response.status_code}: "
            f"{token_response.text}"
        )
    token_payload = token_response.json()
    token_issuer = token_payload.get("iss")
    if token_issuer and auth_server.issuer and token_issuer != auth_server.issuer:
        raise CliError("Token issuer did not match discovered metadata.")

    profile = Profile(
        profile_id=uuid4().hex,
        resource_url=resource_url,
        auth_mode=AUTH_MODE_AUTH_CODE,
        issuer=auth_server.issuer,
        authorization_server_metadata_url=auth_server.metadata_url,
        token_endpoint=auth_server.token_endpoint,
        authorization_endpoint=auth_server.authorization_endpoint,
        device_authorization_endpoint=auth_server.device_authorization_endpoint,
        registration_endpoint=auth_server.registration_endpoint,
        client_id=resolved_client_id,
        token_endpoint_auth_method="none",
        redirect_uri=resolved_redirect_uri,
        dynamic_client_registration=registration_payload,
    )
    profile.set_token_response(token_payload)
    return profile


def _register_client(
    client,
    auth_server: AuthorizationServerMetadata,
    redirect_uri: str,
    *,
    scope: str | None,
):
    payload = {
        "client_name": "mcp-auth CLI public client",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    if scope:
        payload["scope"] = scope
    response = client.post(auth_server.registration_endpoint, json=payload)
    if response.status_code >= 400:
        raise CliError(f"Dynamic registration failed: HTTP {response.status_code}: {response.text}")
    body = response.json()
    if "client_id" not in body:
        raise CliError("Dynamic registration response did not contain a client_id.")
    return body


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _is_loopback_redirect(redirect_uri: str) -> bool:
    parsed = urlparse(redirect_uri)
    return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}


class _LoopbackCallbackServer:
    def __init__(self, host: str, port: int, path: str) -> None:
        self._received_url: str | None = None
        self._event = threading.Event()
        self._path = path
        self._server = HTTPServer(
            (host, port),
            _callback_handler(self),
        )
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @classmethod
    def create(cls, *, host: str, port: int, path: str) -> _LoopbackCallbackServer:
        return cls(host, port, path)

    @classmethod
    def from_redirect_uri(cls, redirect_uri: str) -> _LoopbackCallbackServer:
        parsed = urlparse(redirect_uri)
        if parsed.scheme != "http" or parsed.hostname is None or parsed.port is None:
            raise CliError("Loopback redirect URIs must be absolute http:// URLs with a port.")
        return cls(parsed.hostname, parsed.port, parsed.path or "/")

    @property
    def redirect_uri(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}{self._path}"

    def start(self) -> None:
        self._thread.start()

    def wait_for_url(self, *, timeout: int) -> str | None:
        if self._event.wait(timeout):
            return self._received_url
        return None

    def set_result(self, url: str) -> None:
        self._received_url = url
        self._event.set()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=1)


def _callback_handler(parent: _LoopbackCallbackServer):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parent.set_result(f"http://{self.headers['Host']}{self.path}")
            body = b"Authorization received. You can close this window."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            _ = (format, args)

    return Handler
