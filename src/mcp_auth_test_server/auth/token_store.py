"""In-memory storage for mock OAuth clients, authorization codes, and access tokens."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import compare_digest, token_urlsafe

AUTHORIZATION_CODE_TTL_SECONDS = 300
ACCESS_TOKEN_TTL_SECONDS = 3600


@dataclass(slots=True)
class ClientRecord:
    """Registered OAuth client metadata."""

    client_id: str
    token_endpoint_auth_method: str
    grant_types: tuple[str, ...]
    response_types: tuple[str, ...]
    redirect_uris: tuple[str, ...]
    scope: str
    client_name: str | None
    client_id_issued_at: int
    client_secret: str | None = None
    client_secret_expires_at: int = 0


@dataclass(slots=True)
class AuthorizationCodeRecord:
    """Authorization code state captured during the authorize redirect flow."""

    code: str
    client_id: str
    redirect_uri: str
    scope: str
    resource: str
    code_challenge: str
    code_challenge_method: str
    expires_at: datetime


@dataclass(slots=True)
class AccessTokenRecord:
    """Access token metadata for protected MCP resources."""

    access_token: str
    client_id: str
    scope: str
    grant_type: str
    audience: str | None
    issuer: str | None
    expires_at: datetime
    token_type: str = "Bearer"


class OAuthTokenStore:
    """Simple in-memory store for OAuth state."""

    def __init__(self) -> None:
        self._clients: dict[str, ClientRecord] = {}
        self._authorization_codes: dict[str, AuthorizationCodeRecord] = {}
        self._access_tokens: dict[str, AccessTokenRecord] = {}
        self._seed_mock_clients()

    def reset(self) -> None:
        """Clear all in-memory OAuth state."""

        self._clients.clear()
        self._authorization_codes.clear()
        self._access_tokens.clear()
        self._seed_mock_clients()

    def register_client(
        self,
        *,
        token_endpoint_auth_method: str,
        grant_types: list[str],
        response_types: list[str],
        redirect_uris: list[str],
        scope: str,
        client_name: str | None,
        client_secret: str | None = None,
    ) -> ClientRecord:
        """Persist a dynamically registered OAuth client."""

        issued_at = int(self._now().timestamp())
        record = ClientRecord(
            client_id=token_urlsafe(18),
            client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            grant_types=tuple(grant_types),
            response_types=tuple(response_types),
            redirect_uris=tuple(redirect_uris),
            scope=scope,
            client_name=client_name,
            client_id_issued_at=issued_at,
            client_secret_expires_at=0,
        )
        self._clients[record.client_id] = record
        return record

    def add_client(
        self,
        *,
        client_id: str,
        token_endpoint_auth_method: str,
        grant_types: list[str],
        response_types: list[str],
        redirect_uris: list[str],
        scope: str,
        client_name: str | None,
        client_secret: str | None = None,
    ) -> ClientRecord:
        """Add a fixed client record used by seeded mock fixtures."""

        record = ClientRecord(
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            grant_types=tuple(grant_types),
            response_types=tuple(response_types),
            redirect_uris=tuple(redirect_uris),
            scope=scope,
            client_name=client_name,
            client_id_issued_at=int(self._now().timestamp()),
            client_secret_expires_at=0,
        )
        self._clients[record.client_id] = record
        return record

    def get_client(self, client_id: str) -> ClientRecord | None:
        """Return a registered client by ID."""

        return self._clients.get(client_id)

    def is_valid_client_credentials(self, *, client_id: str, client_secret: str) -> bool:
        """Return True when the supplied mock client credentials are valid."""

        record = self._clients.get(client_id)
        if record is None or record.client_secret is None:
            return False
        return compare_digest(client_secret, record.client_secret)

    def issue_authorization_code(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str,
        resource: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> AuthorizationCodeRecord:
        """Create and persist a short-lived authorization code."""

        record = AuthorizationCodeRecord(
            code=token_urlsafe(24),
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            resource=resource,
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
        grant_type: str,
        audience: str | None = None,
        issuer: str | None = None,
    ) -> AccessTokenRecord:
        """Create and persist a bearer access token."""

        record = AccessTokenRecord(
            access_token=token_urlsafe(32),
            client_id=client_id,
            scope=scope,
            grant_type=grant_type,
            audience=audience,
            issuer=issuer,
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

    def _seed_mock_clients(self) -> None:
        """Install the fixed clients used by earlier project phases."""

        self.add_client(
            client_id="phase-5-public-client",
            token_endpoint_auth_method="none",
            grant_types=["authorization_code"],
            response_types=["code"],
            redirect_uris=["https://client.example/callback"],
            scope="mcp:read",
            client_name="Phase 5 Public Client",
        )
        self.add_client(
            client_id="phase-6-service-client",
            client_secret="phase-6-service-secret",
            token_endpoint_auth_method="client_secret_post",
            grant_types=["client_credentials"],
            response_types=[],
            redirect_uris=[],
            scope="mcp:read mcp:write",
            client_name="Phase 6 Service Client",
        )
        self.add_client(
            client_id="phase-7-public-client",
            token_endpoint_auth_method="none",
            grant_types=["authorization_code"],
            response_types=["code"],
            redirect_uris=["https://client.example/oauth-v21/callback"],
            scope="mcp:read",
            client_name="Phase 7 Public Client",
        )


oauth_token_store = OAuthTokenStore()
