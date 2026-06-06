"""Shared models for the MCP auth CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

AUTH_MODE_BEARER = "bearer"
AUTH_MODE_AUTH_CODE = "auth-code"
AUTH_MODE_DEVICE = "device"
AUTH_MODE_CLIENT_CREDS = "client-creds"
AUTH_MODES = (
    AUTH_MODE_BEARER,
    AUTH_MODE_AUTH_CODE,
    AUTH_MODE_DEVICE,
    AUTH_MODE_CLIENT_CREDS,
)
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


@dataclass(slots=True)
class ProtectedResourceMetadata:
    resource: str
    authorization_servers: list[str] = field(default_factory=list)
    bearer_methods_supported: list[str] = field(default_factory=list)
    scopes_supported: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AuthorizationServerMetadata:
    metadata_url: str
    issuer: str | None
    authorization_endpoint: str | None
    device_authorization_endpoint: str | None
    token_endpoint: str | None
    registration_endpoint: str | None
    grant_types_supported: list[str] = field(default_factory=list)
    token_endpoint_auth_methods_supported: list[str] = field(default_factory=list)
    response_types_supported: list[str] = field(default_factory=list)
    scopes_supported: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DiscoveryResult:
    resource_url: str
    resource_metadata_url: str | None = None
    protected_resource_metadata: ProtectedResourceMetadata | None = None
    authorization_servers: list[AuthorizationServerMetadata] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Profile:
    profile_id: str
    resource_url: str
    auth_mode: str
    issuer: str | None = None
    authorization_server_metadata_url: str | None = None
    token_endpoint: str | None = None
    authorization_endpoint: str | None = None
    device_authorization_endpoint: str | None = None
    registration_endpoint: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: str | None = None
    scope: str | None = None
    token_type: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    token_endpoint_auth_method: str | None = None
    redirect_uri: str | None = None
    dynamic_client_registration: dict[str, Any] | None = None
    created_at: str = field(default_factory=lambda: utcnow().isoformat())
    last_used_at: str = field(default_factory=lambda: utcnow().isoformat())

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Profile:
        return cls(**payload)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def touch(self) -> None:
        self.last_used_at = utcnow().isoformat()

    def expiry_datetime(self) -> datetime | None:
        return parse_datetime(self.expires_at)

    def is_access_token_valid(self, *, skew_seconds: int = 30) -> bool:
        if not self.access_token:
            return False
        expiry = self.expiry_datetime()
        if expiry is None:
            return True
        return expiry > utcnow() + timedelta(seconds=skew_seconds)

    def set_token_response(self, token_payload: dict[str, Any]) -> None:
        self.access_token = _string_or_none(token_payload.get("access_token"))
        self.refresh_token = _string_or_none(
            token_payload.get("refresh_token"),
            default=self.refresh_token,
        )
        self.scope = _string_or_none(token_payload.get("scope"))
        self.token_type = _string_or_none(token_payload.get("token_type"))
        expires_in = token_payload.get("expires_in")
        if isinstance(expires_in, int):
            self.expires_at = (utcnow() + timedelta(seconds=expires_in)).isoformat()
        self.touch()

    def redacted_dict(self) -> dict[str, Any]:
        payload = self.to_dict()
        for field_name in ("access_token", "refresh_token", "client_secret"):
            value = payload.get(field_name)
            if isinstance(value, str) and value:
                payload[field_name] = redact_secret(value)
        return payload


def redact_secret(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _string_or_none(value: Any, *, default: str | None = None) -> str | None:
    if isinstance(value, str):
        return value
    return default
