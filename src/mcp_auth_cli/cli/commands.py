"""Argument parsing and command dispatch for the MCP auth CLI."""

from __future__ import annotations

import argparse
import json
from typing import Any

import httpx

from mcp_auth_cli.auth.auth_code import login_with_authorization_code
from mcp_auth_cli.auth.bearer import login_with_bearer
from mcp_auth_cli.auth.client_credentials import login_with_client_credentials
from mcp_auth_cli.auth.device_code import login_with_device_code
from mcp_auth_cli.auth.discovery import (
    discover,
    pick_authorization_server,
    supported_auth_modes,
)
from mcp_auth_cli.auth.strategies import LoginContext, select_auth_mode
from mcp_auth_cli.auth.token_manager import ensure_valid_access_token
from mcp_auth_cli.cli.ui import TerminalUI
from mcp_auth_cli.errors import CliError
from mcp_auth_cli.mcp.client import build_jsonrpc_payload, call_mcp
from mcp_auth_cli.models import (
    AUTH_MODE_AUTH_CODE,
    AUTH_MODE_BEARER,
    AUTH_MODE_CLIENT_CREDS,
    AUTH_MODE_DEVICE,
)
from mcp_auth_cli.profiles.store import ProfileStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-auth", description="Server-agnostic MCP auth CLI")
    parser.add_argument("--verbose", action="store_true", help="Show protocol-level details.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover_parser = subparsers.add_parser("discover")
    _add_resource_discovery_args(discover_parser)

    login_parser = subparsers.add_parser("login")
    _add_resource_discovery_args(login_parser)
    login_parser.add_argument(
        "--auth-mode",
        choices=["auth-code", "device", "client-creds", "bearer"],
    )
    login_parser.add_argument("--register", action="store_true")
    login_parser.add_argument("--client-id")
    login_parser.add_argument("--client-secret")
    login_parser.add_argument("--scope")
    login_parser.add_argument("--redirect-uri")
    login_parser.add_argument("--listen-port", type=int)
    login_parser.add_argument("--open-browser", action="store_true")
    login_parser.add_argument("--bearer-token")

    call_parser = subparsers.add_parser("call")
    call_parser.add_argument("resource_url")
    call_parser.add_argument("method")
    call_parser.add_argument("--params", help="JSON object for JSON-RPC params.")
    call_parser.add_argument("--tool-name")
    call_parser.add_argument("--tool-arguments", help="JSON object for tools/call arguments.")
    call_parser.add_argument("--request-id")
    call_parser.add_argument("--profile-id")

    profile_parser = subparsers.add_parser("profile")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_command", required=True)
    profile_subparsers.add_parser("list")
    show_parser = profile_subparsers.add_parser("show")
    show_parser.add_argument("profile_id", nargs="?")
    show_parser.add_argument("--resource-url")
    use_parser = profile_subparsers.add_parser("use")
    use_parser.add_argument("profile_id")
    use_parser.add_argument("resource_url")
    delete_parser = profile_subparsers.add_parser("delete")
    delete_parser.add_argument("profile_id")

    logout_parser = subparsers.add_parser("logout")
    logout_parser.add_argument("resource_url")
    logout_parser.add_argument("--keep-client", action="store_true")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    client_factory=None,
    ui: TerminalUI | None = None,
    store: ProfileStore | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    resolved_ui = ui or TerminalUI(verbose=args.verbose)
    resolved_store = store or ProfileStore()
    resolved_client_factory = client_factory or _default_client_factory

    try:
        if args.command == "profile":
            return _handle_profile(args, store=resolved_store, ui=resolved_ui)
        if args.command == "logout":
            return _handle_logout(args, store=resolved_store, ui=resolved_ui)

        with resolved_client_factory() as client:
            if args.command == "discover":
                return _handle_discover(args, client=client, ui=resolved_ui)
            if args.command == "login":
                return _handle_login(args, client=client, ui=resolved_ui, store=resolved_store)
            if args.command == "call":
                return _handle_call(args, client=client, ui=resolved_ui, store=resolved_store)
    except CliError as exc:
        resolved_ui.error(str(exc))
        return 1
    return 0


def _handle_discover(args, *, client, ui: TerminalUI) -> int:
    ui.step(f"Discovering auth options for {args.resource_url}")
    result = discover(
        client,
        resource_url=args.resource_url,
        resource_metadata_url=args.resource_metadata_url,
        authorization_server=args.authorization_server,
        ui=ui,
    )
    modes = supported_auth_modes(result)
    ui.info(f"Supported auth modes: {', '.join(modes)}")
    if result.protected_resource_metadata is not None:
        scopes = result.protected_resource_metadata.scopes_supported
        if scopes:
            ui.info(f"Scopes: {', '.join(scopes)}")
    for metadata in result.authorization_servers:
        ui.info(f"Authorization server: {metadata.metadata_url}")
        if metadata.token_endpoint:
            ui.info(f"Token endpoint: {metadata.token_endpoint}")
        if metadata.authorization_endpoint:
            ui.info(f"Authorization endpoint: {metadata.authorization_endpoint}")
        if metadata.device_authorization_endpoint:
            ui.info(f"Device authorization endpoint: {metadata.device_authorization_endpoint}")
        if ui.verbose:
            ui.dump_json(metadata.raw)
    for warning in result.warnings:
        ui.info(f"Warning: {warning}")
    return 0


def _handle_login(args, *, client, ui: TerminalUI, store: ProfileStore) -> int:
    ui.step(f"Preparing login for {args.resource_url}")
    existing_profile = store.get_active_profile(args.resource_url)
    discovery_result = discover(
        client,
        resource_url=args.resource_url,
        resource_metadata_url=args.resource_metadata_url,
        authorization_server=args.authorization_server,
        ui=ui,
    )
    login_context = LoginContext(
        resource_url=args.resource_url,
        scope=args.scope,
        auth_mode=args.auth_mode,
        register=args.register,
        client_id=args.client_id,
        client_secret=args.client_secret,
        redirect_uri=args.redirect_uri,
        listen_port=args.listen_port,
        open_browser=args.open_browser,
        bearer_token=args.bearer_token,
    )
    auth_mode = select_auth_mode(
        discovery_result,
        explicit_mode=login_context.auth_mode,
        existing_profile=existing_profile,
        client_id=login_context.client_id,
        client_secret=login_context.client_secret,
    )
    ui.step(f"Using auth mode: {auth_mode}")

    if auth_mode == AUTH_MODE_BEARER:
        profile = login_with_bearer(
            ui=ui,
            resource_url=login_context.resource_url,
            bearer_token=login_context.bearer_token,
        )
    else:
        auth_server = pick_authorization_server(discovery_result, auth_mode)
        if auth_mode == AUTH_MODE_CLIENT_CREDS:
            profile = login_with_client_credentials(
                client,
                ui=ui,
                resource_url=login_context.resource_url,
                auth_server=auth_server,
                scope=login_context.scope,
                client_id=login_context.client_id,
                client_secret=login_context.client_secret,
                register=login_context.register,
            )
        elif auth_mode == AUTH_MODE_DEVICE:
            profile = login_with_device_code(
                client,
                ui=ui,
                resource_url=login_context.resource_url,
                auth_server=auth_server,
                scope=login_context.scope,
                client_id=login_context.client_id,
                register=login_context.register,
            )
        elif auth_mode == AUTH_MODE_AUTH_CODE:
            profile = login_with_authorization_code(
                client,
                ui=ui,
                resource_url=login_context.resource_url,
                auth_server=auth_server,
                scope=login_context.scope,
                client_id=login_context.client_id,
                redirect_uri=login_context.redirect_uri,
                register=login_context.register,
                listen_port=login_context.listen_port,
                open_browser=login_context.open_browser,
            )
        else:
            raise CliError(f"Unsupported auth mode: {auth_mode}")
    store.upsert_active_profile(profile)
    ui.info(f"Saved active profile {profile.profile_id} for {profile.resource_url}")
    return 0


def _handle_call(args, *, client, ui: TerminalUI, store: ProfileStore) -> int:
    if args.profile_id:
        profile = store.get_profile(args.profile_id)
    else:
        profile = store.get_active_profile(args.resource_url)
    if profile is None:
        raise CliError("No active profile found for this resource. Run login first.")
    profile = ensure_valid_access_token(client, profile, resource_url=args.resource_url, ui=ui)
    store.upsert_active_profile(profile)

    payload = build_jsonrpc_payload(
        method=args.method,
        params=_call_params_from_args(args),
        request_id=args.request_id,
    )
    response_body = call_mcp(
        client,
        resource_url=args.resource_url,
        access_token=profile.access_token,
        payload=payload,
    )
    ui.dump_json(response_body)
    return 0


def _handle_profile(args, *, store: ProfileStore, ui: TerminalUI) -> int:
    if args.profile_command == "list":
        profiles = store.list_profiles()
        for profile in profiles:
            ui.info(f"{profile.profile_id} {profile.auth_mode} {profile.resource_url}")
        return 0
    if args.profile_command == "show":
        profile = None
        if args.profile_id:
            profile = store.get_profile(args.profile_id)
        elif args.resource_url:
            profile = store.get_active_profile(args.resource_url)
        if profile is None:
            raise CliError("Profile not found.")
        ui.dump_json(profile.redacted_dict())
        return 0
    if args.profile_command == "use":
        profile = store.get_profile(args.profile_id)
        if profile is None:
            raise CliError("Profile not found.")
        store.set_active_profile(args.resource_url, profile.profile_id)
        ui.info(f"Active profile for {args.resource_url} is now {args.profile_id}")
        return 0
    if args.profile_command == "delete":
        store.delete_profile(args.profile_id)
        ui.info(f"Deleted profile {args.profile_id}")
        return 0
    raise CliError(f"Unsupported profile subcommand: {args.profile_command}")


def _handle_logout(args, *, store: ProfileStore, ui: TerminalUI) -> int:
    profile = store.get_active_profile(args.resource_url)
    if profile is None:
        raise CliError("No active profile found for this resource.")
    if args.keep_client:
        profile.access_token = None
        profile.refresh_token = None
        profile.expires_at = None
        store.save_profile(profile, make_active=False)
        ui.info(f"Cleared tokens from profile {profile.profile_id}")
        return 0
    store.delete_profile(profile.profile_id)
    ui.info(f"Logged out from {args.resource_url}")
    return 0


def _add_resource_discovery_args(parser) -> None:
    parser.add_argument("resource_url")
    parser.add_argument("--resource-metadata-url")
    parser.add_argument("--authorization-server")


def _call_params_from_args(args) -> dict[str, Any]:
    if args.method == "initialize":
        return {}
    if args.method == "tools/list":
        return {}
    if args.method == "tools/call":
        if not args.tool_name:
            raise CliError("--tool-name is required for tools/call")
        arguments = _parse_json_object(args.tool_arguments, flag_name="--tool-arguments")
        return {"name": args.tool_name, "arguments": arguments}
    return _parse_json_object(args.params, flag_name="--params")


def _parse_json_object(raw: str | None, *, flag_name: str) -> dict[str, Any]:
    if raw is None or raw == "":
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CliError(f"{flag_name} must be valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CliError(f"{flag_name} must decode to a JSON object.")
    return payload


def _default_client_factory():
    return httpx.Client(follow_redirects=False, timeout=10.0)
