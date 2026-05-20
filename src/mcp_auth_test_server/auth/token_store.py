"""In-memory storage for mock OAuth authorization codes and access tokens."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe

AUTHORIZATION_CODE_TTL_SECONDS = 300
ACCESS_TOKEN_TTL_SECONDS = 3600


@dataclass(slots=True)
class AuthorizationCodeRecord:
    """Authorization code state captured during the authorize redirect flow."""

    code: str
    client_id: str
    redirect_uri: str
    scope: str
    code_challenge: str
    code_challenge_method: str
    expires_at: datetime


@dataclass(slots=True)
class AccessTokenRecord:
    """Access token metadata for protected MCP resources."""

    access_token: str
    client_id: str
    scope: str
    expires_at: datetime
    token_type: str = "Bearer"


class OAuthTokenStore:
    """Simple in-memory store for OAuth state."""

    def __init__(self) -> None:
        self._authorization_codes: dict[str, AuthorizationCodeRecord] = {}
        self._access_tokens: dict[str, AccessTokenRecord] = {}

    def reset(self) -> None:
        """Clear all in-memory OAuth state."""

        self._authorization_codes.clear()
        self._access_tokens.clear()

    def issue_authorization_code(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> AuthorizationCodeRecord:
        """Create and persist a short-lived authorization code."""

        record = AuthorizationCodeRecord(
            code=token_urlsafe(24),
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=self._now() + timedelta(seconds=AUTHORIZATION_CODE_TTL_SECONDS),
        )
        self._authorization_codes[record.code] = record
        return record

    def consume_authorization_code(
        self,
        *,
        code: str,
        client_id: str,
        redirect_uri: str,
    ) -> AuthorizationCodeRecord | None:
        """Atomically consume an authorization code if it is still valid."""

        record = self._authorization_codes.pop(code, None)
        if record is None:
            return None
        if record.expires_at < self._now():
            return None
        if record.client_id != client_id or record.redirect_uri != redirect_uri:
            return None
        return record

    def issue_access_token(
        self,
        *,
        client_id: str,
        scope: str,
    ) -> AccessTokenRecord:
        """Create and persist a bearer access token."""

        record = AccessTokenRecord(
            access_token=token_urlsafe(32),
            client_id=client_id,
            scope=scope,
            expires_at=self._now() + timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS),
        )
        self._access_tokens[record.access_token] = record
        return record

    def get_access_token(self, token: str) -> AccessTokenRecord | None:
        """Return an access token if it exists and has not expired."""

        record = self._access_tokens.get(token)
        if record is None:
            return None
        if record.expires_at < self._now():
            self._access_tokens.pop(token, None)
            return None
        return record

    @staticmethod
    def _now() -> datetime:
        return datetime.now(tz=UTC)


oauth_token_store = OAuthTokenStore()
