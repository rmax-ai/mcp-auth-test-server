"""Tests for the standalone MCP auth CLI."""

from __future__ import annotations

import io
import stat
import threading
import time
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from mcp_auth_cli.auth.auth_code import login_with_authorization_code
from mcp_auth_cli.auth.client_credentials import login_with_client_credentials
from mcp_auth_cli.auth.device_code import login_with_device_code
from mcp_auth_cli.auth.discovery import discover, pick_authorization_server, supported_auth_modes
from mcp_auth_cli.auth.strategies import select_auth_mode
from mcp_auth_cli.cli.commands import main
from mcp_auth_cli.cli.ui import TerminalUI
from mcp_auth_cli.models import (
    AUTH_MODE_BEARER,
    AUTH_MODE_CLIENT_CREDS,
    AUTH_MODE_DEVICE,
    Profile,
)
from mcp_auth_cli.profiles.store import ProfileStore
from mcp_auth_test_server.app import app
from mcp_auth_test_server.auth.bearer import reset_minted_tokens
from mcp_auth_test_server.auth.token_store import oauth_token_store


def _test_client() -> TestClient:
    return TestClient(app, base_url="http://test")


@pytest.fixture(autouse=True)
def reset_state():
    oauth_token_store.reset()
    reset_minted_tokens()
    yield
    oauth_token_store.reset()
    reset_minted_tokens()


def test_profile_store_persists_active_profile_with_restrictive_permissions(tmp_path):
    store = ProfileStore(home=tmp_path)
    profile = Profile(
        profile_id="profile-1",
        resource_url="http://test/mcp/oauth",
        auth_mode=AUTH_MODE_BEARER,
        access_token="secret-token",
    )

    store.upsert_active_profile(profile)

    assert store.get_active_profile("http://test/mcp/oauth") is not None
    mode = stat.S_IMODE(store.path.stat().st_mode)
    assert mode == 0o600


def test_discovery_and_mode_selection_prefer_device_for_generic_cli():
    with _test_client() as client:
        result = discover(client, resource_url="http://test/mcp/oauth")

    assert supported_auth_modes(result) == ["bearer", "client-creds", "device", "auth-code"]
    assert (
        select_auth_mode(
            result,
            explicit_mode=None,
            existing_profile=None,
            client_id=None,
            client_secret=None,
        )
        == AUTH_MODE_DEVICE
    )


def test_auth_code_login_uses_loopback_listener_with_dynamic_registration():
    output = io.StringIO()
    ui = TerminalUI(verbose=True, out=output)
    with _test_client() as client:
        discovery_result = discover(client, resource_url="http://test/mcp/oauth")
        auth_server = pick_authorization_server(discovery_result, "auth-code")

        def approve() -> None:
            while True:
                lines = output.getvalue().splitlines()
                if lines:
                    authorization_url = lines[-1]
                    break
                time.sleep(0.01)
            with _test_client() as browser:
                authorize = browser.get(authorization_url)
                assert authorize.status_code == 200
                params = parse_qs(urlparse(authorization_url).query, keep_blank_values=True)
                consent_data = {
                    key: values[0] for key, values in params.items()
                } | {"decision": "approve"}
                consent = browser.post(
                    "/oauth/authorize/consent",
                    data=consent_data,
                    follow_redirects=False,
                )
            httpx.get(consent.headers["location"], timeout=5.0)

        approval_thread = threading.Thread(target=approve, daemon=True)
        approval_thread.start()
        profile = login_with_authorization_code(
            client,
            ui=ui,
            resource_url="http://test/mcp/oauth",
            auth_server=auth_server,
            scope="mcp:read",
            client_id=None,
            redirect_uri=None,
            register=True,
            listen_port=None,
            open_browser=False,
        )
        approval_thread.join(timeout=1)

    assert profile.access_token is not None
    assert profile.refresh_token is not None
    assert profile.client_id is not None
    assert profile.redirect_uri is not None
    assert profile.redirect_uri.startswith("http://127.0.0.1:")


def test_device_login_polls_until_approved_with_registered_client():
    class AutoApprovingClient:
        def __init__(self, inner_client: TestClient) -> None:
            self.inner_client = inner_client

        def get(self, *args, **kwargs):
            return self.inner_client.get(*args, **kwargs)

        def post(self, url, *args, **kwargs):
            response = self.inner_client.post(url, *args, **kwargs)
            if str(url).endswith("/oauth/device/authorize"):
                user_code = response.json()["user_code"]

                def approve() -> None:
                    time.sleep(0.05)
                    with _test_client() as approver:
                        approver.post(
                            "/oauth/device/verify/consent",
                            data={"user_code": user_code, "decision": "approve"},
                        )

                threading.Thread(target=approve, daemon=True).start()
            return response

    ui = TerminalUI(out=io.StringIO())
    with _test_client() as test_client:
        wrapped = AutoApprovingClient(test_client)
        discovery_result = discover(wrapped, resource_url="http://test/mcp/oauth")
        auth_server = pick_authorization_server(discovery_result, AUTH_MODE_DEVICE)
        profile = login_with_device_code(
            wrapped,
            ui=ui,
            resource_url="http://test/mcp/oauth",
            auth_server=auth_server,
            scope="mcp:read",
            client_id=None,
            register=True,
            max_polls=10,
        )

    assert profile.access_token is not None
    assert profile.refresh_token is not None


def test_call_auto_refreshes_refreshable_profile_and_updates_store(tmp_path):
    store = ProfileStore(home=tmp_path)
    output = io.StringIO()

    with _test_client() as client:
        ui = TerminalUI(out=output)
        discovery_result = discover(client, resource_url="http://test/mcp/oauth")
        auth_server = pick_authorization_server(discovery_result, "auth-code")

        def approve() -> None:
            while True:
                lines = output.getvalue().splitlines()
                if lines:
                    authorization_url = lines[-1]
                    break
                time.sleep(0.01)
            with _test_client() as browser:
                params = parse_qs(urlparse(authorization_url).query, keep_blank_values=True)
                consent_data = {
                    key: values[0] for key, values in params.items()
                } | {"decision": "approve"}
                consent = browser.post(
                    "/oauth/authorize/consent",
                    data=consent_data,
                    follow_redirects=False,
                )
            httpx.get(consent.headers["location"], timeout=5.0)

        approval_thread = threading.Thread(target=approve, daemon=True)
        approval_thread.start()
        profile = login_with_authorization_code(
            client,
            ui=ui,
            resource_url="http://test/mcp/oauth",
            auth_server=auth_server,
            scope="mcp:read",
            client_id=None,
            redirect_uri=None,
            register=True,
            listen_port=None,
            open_browser=False,
        )
        approval_thread.join(timeout=1)
        original_access_token = profile.access_token
        profile.expires_at = (datetime.now(tz=UTC) - timedelta(minutes=5)).isoformat()
        store.upsert_active_profile(profile)

        result = main(
            ["call", "http://test/mcp/oauth", "initialize"],
            client_factory=lambda: nullcontext(client),
            ui=TerminalUI(out=output, err=io.StringIO()),
            store=store,
        )

    assert result == 0
    refreshed = store.get_active_profile("http://test/mcp/oauth")
    assert refreshed is not None
    assert refreshed.access_token != original_access_token
    assert "mcp-auth-test-server" in output.getvalue()


def test_call_reacquires_client_credentials_profile_when_expired(tmp_path):
    store = ProfileStore(home=tmp_path)
    output = io.StringIO()

    with _test_client() as client:
        discovery_result = discover(client, resource_url="http://test/mcp/oauth")
        auth_server = pick_authorization_server(discovery_result, AUTH_MODE_CLIENT_CREDS)
        profile = login_with_client_credentials(
            client,
            ui=TerminalUI(out=output),
            resource_url="http://test/mcp/oauth",
            auth_server=auth_server,
            scope="mcp:write",
            client_id=None,
            client_secret=None,
            register=True,
        )
        original_access_token = profile.access_token
        profile.expires_at = (datetime.now(tz=UTC) - timedelta(minutes=5)).isoformat()
        store.upsert_active_profile(profile)

        result = main(
            ["call", "http://test/mcp/oauth", "initialize"],
            client_factory=lambda: nullcontext(client),
            ui=TerminalUI(out=output, err=io.StringIO()),
            store=store,
        )

    assert result == 0
    refreshed = store.get_active_profile("http://test/mcp/oauth")
    assert refreshed is not None
    assert refreshed.access_token != original_access_token


def test_manual_bearer_profile_never_auto_refreshes(tmp_path):
    store = ProfileStore(home=tmp_path)
    errors = io.StringIO()
    profile = Profile(
        profile_id="bearer-profile",
        resource_url="http://test/mcp/bearer-token",
        auth_mode=AUTH_MODE_BEARER,
        access_token="test-bearer-token",
        expires_at=(datetime.now(tz=UTC) - timedelta(minutes=5)).isoformat(),
    )
    store.upsert_active_profile(profile)

    with _test_client() as client:
        result = main(
            ["call", "http://test/mcp/bearer-token", "initialize"],
            client_factory=lambda: nullcontext(client),
            ui=TerminalUI(out=io.StringIO(), err=errors),
            store=store,
        )

    assert result == 1
    assert "Run login again" in errors.getvalue()
