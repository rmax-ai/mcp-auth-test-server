"""OAuth 1.0a HMAC-SHA1 validation for the legacy mock MCP endpoint."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, unquote, urlsplit

OAUTH1_REALM = "mcp-auth-test-server"
OAUTH1_CONSUMER_KEY_ENV_VAR = "MCP_AUTH_TEST_SERVER_OAUTH1_CONSUMER_KEY"
OAUTH1_CONSUMER_SECRET_ENV_VAR = "MCP_AUTH_TEST_SERVER_OAUTH1_CONSUMER_SECRET"
DEFAULT_OAUTH1_CONSUMER_KEY = "phase-8-consumer-key"
DEFAULT_OAUTH1_CONSUMER_SECRET = "phase-8-consumer-secret"
OAUTH1_TIMESTAMP_TOLERANCE_SECONDS = 300


class OAuth1Error(Exception):
    """Raised when an OAuth 1.0a request fails validation."""

    def __init__(self, *, description: str, problem: str = "signature_invalid") -> None:
        super().__init__(description)
        self.description = description
        self.problem = problem

    def to_www_authenticate(self) -> str:
        """Render an OAuth 1.0a challenge header."""

        return (
            f'OAuth realm="{OAUTH1_REALM}", '
            f'oauth_problem="{self.problem}", '
            f'oauth_problem_advice="{self.description}"'
        )


@dataclass(slots=True)
class OAuth1Request:
    """Normalized OAuth 1.0a parameters required for signature validation."""

    consumer_key: str
    signature_method: str
    timestamp: str
    nonce: str
    signature: str
    version: str | None
    extra_params: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class NonceStore:
    """In-memory replay protection for OAuth 1.0a nonces."""

    _seen: set[tuple[str, str, str]] = field(default_factory=set)

    def register(self, *, consumer_key: str, timestamp: str, nonce: str) -> None:
        entry = (consumer_key, timestamp, nonce)
        if entry in self._seen:
            raise OAuth1Error(
                description="oauth_timestamp and oauth_nonce were already used",
                problem="nonce_used",
            )
        self._seen.add(entry)

    def reset(self) -> None:
        self._seen.clear()


oauth_v1_nonce_store = NonceStore()


def get_expected_consumer_credentials() -> tuple[str, str]:
    """Return the configured mock OAuth 1.0a consumer credentials."""

    consumer_key = os.getenv(OAUTH1_CONSUMER_KEY_ENV_VAR, DEFAULT_OAUTH1_CONSUMER_KEY)
    consumer_secret = os.getenv(OAUTH1_CONSUMER_SECRET_ENV_VAR, DEFAULT_OAUTH1_CONSUMER_SECRET)
    return consumer_key, consumer_secret


def _percent_encode(value: str) -> str:
    return quote(value, safe="~")


def _parse_authorization_header(authorization_header: str | None) -> OAuth1Request:
    if authorization_header is None:
        raise OAuth1Error(
            description="Missing Authorization header",
            problem="parameter_absent",
        )

    scheme, _, raw_params = authorization_header.partition(" ")
    if scheme.lower() != "oauth" or not raw_params:
        raise OAuth1Error(
            description="Authorization header must use OAuth 1.0a",
            problem="version_rejected",
        )

    params: dict[str, str] = {}
    for part in raw_params.split(","):
        item = part.strip()
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        params[key] = unquote(value)

    consumer_key = params.get("oauth_consumer_key")
    signature_method = params.get("oauth_signature_method")
    timestamp = params.get("oauth_timestamp")
    nonce = params.get("oauth_nonce")
    signature = params.get("oauth_signature")
    version = params.get("oauth_version")

    if not consumer_key:
        raise OAuth1Error(
            description="oauth_consumer_key is required",
            problem="parameter_absent",
        )
    if not signature_method:
        raise OAuth1Error(
            description="oauth_signature_method is required",
            problem="parameter_absent",
        )
    if not timestamp:
        raise OAuth1Error(
            description="oauth_timestamp is required",
            problem="parameter_absent",
        )
    if not nonce:
        raise OAuth1Error(
            description="oauth_nonce is required",
            problem="parameter_absent",
        )
    if not signature:
        raise OAuth1Error(
            description="oauth_signature is required",
            problem="parameter_absent",
        )

    extra_params = {
        key: value
        for key, value in params.items()
        if key
        not in {
            "realm",
            "oauth_consumer_key",
            "oauth_signature_method",
            "oauth_timestamp",
            "oauth_nonce",
            "oauth_signature",
            "oauth_version",
        }
    }

    return OAuth1Request(
        consumer_key=consumer_key,
        signature_method=signature_method,
        timestamp=timestamp,
        nonce=nonce,
        signature=signature,
        version=version,
        extra_params=extra_params,
    )


def _validate_timestamp(timestamp: str) -> None:
    try:
        timestamp_value = int(timestamp)
    except ValueError as exc:
        raise OAuth1Error(
            description="oauth_timestamp must be an integer",
            problem="timestamp_refused",
        ) from exc

    now = int(time.time())
    if abs(now - timestamp_value) > OAUTH1_TIMESTAMP_TOLERANCE_SECONDS:
        raise OAuth1Error(
            description="oauth_timestamp is outside the accepted clock skew",
            problem="timestamp_refused",
        )


def _base_string_uri(url: str) -> str:
    split = urlsplit(url)
    scheme = split.scheme.lower()
    hostname = (split.hostname or "").lower()
    port = split.port

    authority = hostname
    if port is not None:
        is_default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        if not is_default:
            authority = f"{hostname}:{port}"

    path = split.path or "/"
    return f"{scheme}://{authority}{path}"


def _normalize_parameters(url: str, oauth_request: OAuth1Request) -> str:
    items: list[tuple[str, str]] = []

    for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        items.append((_percent_encode(key), _percent_encode(value)))

    oauth_params = {
        "oauth_consumer_key": oauth_request.consumer_key,
        "oauth_signature_method": oauth_request.signature_method,
        "oauth_timestamp": oauth_request.timestamp,
        "oauth_nonce": oauth_request.nonce,
    }
    if oauth_request.version is not None:
        oauth_params["oauth_version"] = oauth_request.version
    oauth_params.update(oauth_request.extra_params)

    for key, value in oauth_params.items():
        items.append((_percent_encode(key), _percent_encode(value)))

    items.sort()
    return "&".join(f"{key}={value}" for key, value in items)


def _build_signature_base_string(method: str, url: str, oauth_request: OAuth1Request) -> str:
    return "&".join(
        [
            _percent_encode(method.upper()),
            _percent_encode(_base_string_uri(url)),
            _percent_encode(_normalize_parameters(url, oauth_request)),
        ]
    )


def _compute_signature(
    *,
    method: str,
    url: str,
    consumer_secret: str,
    oauth_request: OAuth1Request,
) -> str:
    base_string = _build_signature_base_string(method, url, oauth_request)
    signing_key = f"{_percent_encode(consumer_secret)}&"
    digest = hmac.new(
        signing_key.encode("utf-8"),
        base_string.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def validate_oauth_v1_request(
    *,
    method: str,
    url: str,
    authorization_header: str | None,
) -> None:
    """Validate an OAuth 1.0a HMAC-SHA1 Authorization header for a request."""

    oauth_request = _parse_authorization_header(authorization_header)

    if oauth_request.signature_method != "HMAC-SHA1":
        raise OAuth1Error(
            description="oauth_signature_method must be HMAC-SHA1",
            problem="signature_method_rejected",
        )
    if oauth_request.version is not None and oauth_request.version != "1.0":
        raise OAuth1Error(
            description="oauth_version must be 1.0 when provided",
            problem="version_rejected",
        )

    expected_consumer_key, expected_consumer_secret = get_expected_consumer_credentials()
    if oauth_request.consumer_key != expected_consumer_key:
        raise OAuth1Error(
            description="oauth_consumer_key is invalid",
            problem="consumer_key_unknown",
        )

    _validate_timestamp(oauth_request.timestamp)

    expected_signature = _compute_signature(
        method=method,
        url=url,
        consumer_secret=expected_consumer_secret,
        oauth_request=oauth_request,
    )
    if not hmac.compare_digest(oauth_request.signature, expected_signature):
        raise OAuth1Error(
            description="oauth_signature is invalid",
            problem="signature_invalid",
        )

    oauth_v1_nonce_store.register(
        consumer_key=oauth_request.consumer_key,
        timestamp=oauth_request.timestamp,
        nonce=oauth_request.nonce,
    )
