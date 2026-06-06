"""Reusable OpenAPI examples for the mock auth server."""

from __future__ import annotations

from typing import Any

JSON_SCHEMA_OBJECT = {
    "type": "object",
    "additionalProperties": True,
}

JSON_RPC_REQUEST_SCHEMA = {
    "type": "object",
    "required": ["jsonrpc", "method"],
    "properties": {
        "jsonrpc": {"type": "string", "enum": ["2.0"]},
        "id": {
            "oneOf": [
                {"type": "string"},
                {"type": "integer"},
                {"type": "null"},
            ]
        },
        "method": {
            "type": "string",
            "enum": [
                "initialize",
                "notifications/initialized",
                "ping",
                "tools/list",
                "tools/call",
            ],
        },
        "params": JSON_SCHEMA_OBJECT,
    },
    "additionalProperties": False,
}

JSON_RPC_SUCCESS_SCHEMA = {
    "type": "object",
    "required": ["jsonrpc", "id", "result"],
    "properties": {
        "jsonrpc": {"type": "string", "enum": ["2.0"]},
        "id": {
            "oneOf": [
                {"type": "string"},
                {"type": "integer"},
                {"type": "null"},
            ]
        },
        "result": JSON_SCHEMA_OBJECT,
    },
    "additionalProperties": True,
}

JSON_RPC_ERROR_SCHEMA = {
    "type": "object",
    "required": ["jsonrpc", "id", "error"],
    "properties": {
        "jsonrpc": {"type": "string", "enum": ["2.0"]},
        "id": {
            "oneOf": [
                {"type": "string"},
                {"type": "integer"},
                {"type": "null"},
            ]
        },
        "error": {
            "type": "object",
            "required": ["code", "message"],
            "properties": {
                "code": {"type": "integer"},
                "message": {"type": "string"},
                "data": {},
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": False,
}


def json_examples_content(
    *,
    schema: dict[str, Any],
    examples: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "application/json": {
            "schema": schema,
            "examples": examples,
        }
    }


def form_examples_content(
    *,
    schema: dict[str, Any],
    examples: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "application/x-www-form-urlencoded": {
            "schema": schema,
            "examples": examples,
        }
    }


def request_body(
    *,
    content: dict[str, Any],
    required: bool = True,
) -> dict[str, Any]:
    return {
        "requestBody": {
            "required": required,
            "content": content,
        }
    }


def json_response(
    *,
    description: str,
    schema: dict[str, Any] | None = None,
    example: dict[str, Any] | None = None,
) -> dict[str, Any]:
    content: dict[str, Any] = {"application/json": {}}
    if schema is not None:
        content["application/json"]["schema"] = schema
    if example is not None:
        content["application/json"]["example"] = example
    return {
        "description": description,
        "content": content,
    }


MCP_REQUEST_BODY = request_body(
    content=json_examples_content(
        schema=JSON_RPC_REQUEST_SCHEMA,
        examples={
            "initialize": {
                "summary": "Initialize the MCP session",
                "value": {
                    "jsonrpc": "2.0",
                    "id": "init-1",
                    "method": "initialize",
                    "params": {},
                },
            },
            "toolsList": {
                "summary": "List server tools",
                "value": {
                    "jsonrpc": "2.0",
                    "id": "tools-list-1",
                    "method": "tools/list",
                    "params": {},
                },
            },
            "echoTool": {
                "summary": "Call the echo tool",
                "value": {
                    "jsonrpc": "2.0",
                    "id": "tools-call-1",
                    "method": "tools/call",
                    "params": {
                        "name": "echo",
                        "arguments": {
                            "message": "hello from docs",
                            "count": 2,
                            "uppercase": True,
                        },
                    },
                },
            },
        },
    )
)

MCP_RESPONSES = {
    200: json_response(
        description="Successful JSON-RPC response.",
        schema=JSON_RPC_SUCCESS_SCHEMA,
        example={
            "jsonrpc": "2.0",
            "id": "tools-call-1",
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "{'message': 'HELLO FROM DOCS', 'count': 2, 'uppercase': True}",
                    }
                ],
                "structuredContent": {
                    "message": "HELLO FROM DOCS",
                    "count": 2,
                    "uppercase": True,
                },
                "isError": False,
            },
        },
    ),
    204: {"description": "Notification accepted; no JSON-RPC response body is returned."},
    400: json_response(
        description="Invalid JSON-RPC request.",
        schema=JSON_RPC_ERROR_SCHEMA,
        example={
            "jsonrpc": "2.0",
            "id": "tools-call-1",
            "error": {
                "code": -32601,
                "message": "Unknown tool: missing-tool",
            },
        },
    ),
}

UNAUTHORIZED_DETAIL_SCHEMA = {
    "type": "object",
    "required": ["detail"],
    "properties": {"detail": {"type": "string"}},
    "additionalProperties": False,
}

UNAUTHORIZED_RESPONSE = json_response(
    description="Authentication failed.",
    schema=UNAUTHORIZED_DETAIL_SCHEMA,
    example={"detail": "Missing Authorization header"},
)

HEALTH_RESPONSES = {
    200: json_response(
        description="Server health details.",
        schema={
            "type": "object",
            "required": ["status", "version"],
            "properties": {
                "status": {"type": "string"},
                "version": {"type": "string"},
            },
            "additionalProperties": False,
        },
        example={"status": "ok", "version": "0.1.0"},
    )
}

OAUTH_ERROR_SCHEMA = {
    "type": "object",
    "required": ["error", "error_description"],
    "properties": {
        "error": {"type": "string"},
        "error_description": {"type": "string"},
    },
    "additionalProperties": False,
}

OAUTH_ERROR_RESPONSE = json_response(
    description="OAuth validation error.",
    schema=OAUTH_ERROR_SCHEMA,
    example={
        "error": "invalid_request",
        "error_description": "code_challenge_method must be S256",
    },
)

TOKEN_RESPONSE_SCHEMA = {
    "type": "object",
    "required": ["access_token", "token_type", "expires_in", "scope", "aud", "iss"],
    "properties": {
        "access_token": {"type": "string"},
        "token_type": {"type": "string"},
        "expires_in": {"type": "integer"},
        "scope": {"type": "string"},
        "aud": {"type": "string"},
        "iss": {"type": "string"},
        "refresh_token": {"type": "string"},
    },
    "additionalProperties": False,
}

TOKEN_RESPONSE = json_response(
    description="Access token issued.",
    schema=TOKEN_RESPONSE_SCHEMA,
    example={
        "access_token": "access-docs-example",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "mcp:read",
        "aud": "http://test/mcp/oauth",
        "iss": "http://test",
        "refresh_token": "refresh-docs-example",
    },
)

AUTHORIZE_PARAMETERS = [
    {
        "name": "response_type",
        "in": "query",
        "required": True,
        "description": "Must be `code`.",
        "schema": {"type": "string", "enum": ["code"]},
        "example": "code",
    },
    {
        "name": "client_id",
        "in": "query",
        "required": True,
        "schema": {"type": "string"},
        "example": "phase-5-public-client",
    },
    {
        "name": "redirect_uri",
        "in": "query",
        "required": True,
        "description": (
            "Absolute redirect URI registered for the client. "
            "When testing from Swagger UI, prefer a same-origin callback such as "
            "`http://<this-host>/docs/oauth-callback` so the browser can "
            "render the redirected result."
        ),
        "schema": {"type": "string", "format": "uri"},
        "example": "https://client.example/callback",
    },
    {
        "name": "scope",
        "in": "query",
        "required": False,
        "schema": {"type": "string"},
        "example": "mcp:read",
    },
    {
        "name": "state",
        "in": "query",
        "required": False,
        "schema": {"type": "string"},
        "example": "phase-5-state",
    },
    {
        "name": "resource",
        "in": "query",
        "required": True,
        "description": "Protected resource URI. Must match the canonical `/mcp/oauth` resource.",
        "schema": {"type": "string", "format": "uri"},
        "example": "http://test/mcp/oauth",
    },
    {
        "name": "code_challenge",
        "in": "query",
        "required": True,
        "schema": {"type": "string"},
        "example": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGqstwM5lM",
    },
    {
        "name": "code_challenge_method",
        "in": "query",
        "required": True,
        "schema": {"type": "string", "enum": ["S256"]},
        "example": "S256",
    },
    {
        "name": "auto_approve",
        "in": "query",
        "required": False,
        "description": "When `true`, skip the HTML consent page and redirect immediately.",
        "schema": {"type": "string", "enum": ["true"]},
        "example": "true",
    },
]

AUTHORIZE_RESPONSES = {
    200: {
        "description": "Mock consent HTML page.",
        "content": {
            "text/html": {"example": "<html><body><h1>Mock OAuth Consent</h1></body></html>"}
        },
    },
    302: {
        "description": (
            "Redirect to the client redirect URI with an authorization code. "
            "In Swagger UI, use a same-origin callback like `/docs/oauth-callback` "
            "to inspect the redirected query parameters in the browser."
        )
    },
    400: OAUTH_ERROR_RESPONSE,
}

AUTHORIZE_CONSENT_REQUEST_BODY = request_body(
    content=form_examples_content(
        schema={
            "type": "object",
            "required": [
                "client_id",
                "redirect_uri",
                "scope",
                "resource",
                "code_challenge",
                "code_challenge_method",
                "decision",
            ],
            "properties": {
                "client_id": {"type": "string"},
                "redirect_uri": {"type": "string", "format": "uri"},
                "scope": {"type": "string"},
                "state": {"type": "string"},
                "resource": {"type": "string", "format": "uri"},
                "code_challenge": {"type": "string"},
                "code_challenge_method": {"type": "string", "enum": ["S256"]},
                "decision": {"type": "string", "enum": ["approve", "deny"]},
            },
            "additionalProperties": False,
        },
        examples={
            "approve": {
                "summary": "Approve the consent prompt",
                "value": {
                    "client_id": "phase-5-public-client",
                    "redirect_uri": "https://client.example/callback",
                    "scope": "mcp:read",
                    "state": "phase-5-state",
                    "resource": "http://test/mcp/oauth",
                    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGqstwM5lM",
                    "code_challenge_method": "S256",
                    "decision": "approve",
                },
            },
            "deny": {
                "summary": "Deny the consent prompt",
                "value": {
                    "client_id": "phase-5-public-client",
                    "redirect_uri": "https://client.example/callback",
                    "scope": "mcp:read",
                    "state": "phase-5-state",
                    "resource": "http://test/mcp/oauth",
                    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGqstwM5lM",
                    "code_challenge_method": "S256",
                    "decision": "deny",
                },
            },
        },
    )
)

TOKEN_REQUEST_BODY = request_body(
    content=form_examples_content(
        schema={
            "oneOf": [
                {
                    "type": "object",
                    "required": [
                        "grant_type",
                        "code",
                        "redirect_uri",
                        "client_id",
                        "code_verifier",
                        "resource",
                    ],
                    "properties": {
                        "grant_type": {"type": "string", "enum": ["authorization_code"]},
                        "code": {"type": "string"},
                        "redirect_uri": {"type": "string", "format": "uri"},
                        "client_id": {"type": "string"},
                        "code_verifier": {"type": "string"},
                        "resource": {"type": "string", "format": "uri"},
                    },
                    "additionalProperties": True,
                },
                {
                    "type": "object",
                    "required": ["grant_type", "refresh_token", "client_id"],
                    "properties": {
                        "grant_type": {"type": "string", "enum": ["refresh_token"]},
                        "refresh_token": {"type": "string"},
                        "client_id": {"type": "string"},
                        "resource": {"type": "string", "format": "uri"},
                    },
                    "additionalProperties": True,
                },
                {
                    "type": "object",
                    "required": ["grant_type", "client_id", "client_secret"],
                    "properties": {
                        "grant_type": {"type": "string", "enum": ["client_credentials"]},
                        "client_id": {"type": "string"},
                        "client_secret": {"type": "string"},
                        "scope": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
                {
                    "type": "object",
                    "required": ["grant_type", "client_id", "device_code"],
                    "properties": {
                        "grant_type": {
                            "type": "string",
                            "enum": ["urn:ietf:params:oauth:grant-type:device_code"],
                        },
                        "client_id": {"type": "string"},
                        "device_code": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            ]
        },
        examples={
            "authorizationCode": {
                "summary": "Exchange an authorization code",
                "value": {
                    "grant_type": "authorization_code",
                    "code": "authorization-code-from-redirect",
                    "redirect_uri": "https://client.example/callback",
                    "client_id": "phase-5-public-client",
                    "code_verifier": "phase-10-verifier",
                    "resource": "http://test/mcp/oauth",
                },
            },
            "refreshToken": {
                "summary": "Refresh an access token",
                "value": {
                    "grant_type": "refresh_token",
                    "refresh_token": "refresh-docs-example",
                    "client_id": "phase-5-public-client",
                    "resource": "http://test/mcp/oauth",
                },
            },
            "clientCredentials": {
                "summary": "Client-credentials token request",
                "value": {
                    "grant_type": "client_credentials",
                    "client_id": "phase-6-service-client",
                    "client_secret": "phase-6-service-secret",
                    "scope": "mcp:read",
                },
            },
            "deviceCode": {
                "summary": "Device code token request",
                "value": {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": "phase-11-device-client",
                    "device_code": "device-docs-example",
                },
            },
        },
    )
)

DYNAMIC_CLIENT_REGISTRATION_REQUEST_BODY = request_body(
    content=json_examples_content(
        schema={
            "type": "object",
            "properties": {
                "redirect_uris": {
                    "type": "array",
                    "items": {"type": "string", "format": "uri"},
                },
                "grant_types": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "response_types": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "token_endpoint_auth_method": {"type": "string"},
                "scope": {"type": "string"},
                "client_name": {"type": "string"},
            },
            "additionalProperties": True,
        },
        examples={
            "publicClient": {
                "summary": "Register a public PKCE client",
                "value": {
                    "redirect_uris": ["https://client.example/phase-10/callback"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                    "scope": "mcp:read",
                    "client_name": "Docs Example Public Client",
                },
            },
            "serviceClient": {
                "summary": "Register a confidential service client",
                "value": {
                    "grant_types": ["client_credentials"],
                    "token_endpoint_auth_method": "client_secret_post",
                    "scope": "mcp:read",
                    "client_name": "Docs Example Service Client",
                },
            },
            "deviceClient": {
                "summary": "Register a public device-flow client",
                "value": {
                    "grant_types": [
                        "urn:ietf:params:oauth:grant-type:device_code",
                        "refresh_token",
                    ],
                    "token_endpoint_auth_method": "none",
                    "scope": "mcp:read",
                    "client_name": "Docs Example Device Client",
                },
            },
        },
    )
)

DYNAMIC_CLIENT_REGISTRATION_RESPONSE = {
    201: json_response(
        description="Client registration succeeded.",
        schema={
            "type": "object",
            "required": [
                "client_id",
                "client_id_issued_at",
                "token_endpoint_auth_method",
                "grant_types",
                "response_types",
                "scope",
            ],
            "properties": {
                "client_id": {"type": "string"},
                "client_id_issued_at": {"type": "integer"},
                "token_endpoint_auth_method": {"type": "string"},
                "grant_types": {"type": "array", "items": {"type": "string"}},
                "response_types": {"type": "array", "items": {"type": "string"}},
                "scope": {"type": "string"},
                "redirect_uris": {
                    "type": "array",
                    "items": {"type": "string", "format": "uri"},
                },
                "client_name": {"type": "string"},
                "client_secret": {"type": "string"},
                "client_secret_expires_at": {"type": "integer"},
            },
            "additionalProperties": True,
        },
        example={
            "client_id": "client-docs-example",
            "client_id_issued_at": 1710000000,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "mcp:read",
            "redirect_uris": ["https://client.example/phase-10/callback"],
            "client_name": "Docs Example Public Client",
        },
    ),
    400: OAUTH_ERROR_RESPONSE,
}

PROTECTED_RESOURCE_METADATA_PARAMETERS = [
    {
        "name": "resource",
        "in": "query",
        "required": False,
        "description": "Optional protected resource URL to resolve metadata for.",
        "schema": {"type": "string", "format": "uri"},
        "example": "http://test/mcp/oauth",
    }
]

PROTECTED_RESOURCE_METADATA_RESPONSES = {
    200: json_response(
        description="Protected resource metadata document.",
        schema={
            "type": "object",
            "required": [
                "resource",
                "authorization_servers",
                "bearer_methods_supported",
                "scopes_supported",
            ],
            "properties": {
                "resource": {"type": "string", "format": "uri"},
                "authorization_servers": {
                    "type": "array",
                    "items": {"type": "string", "format": "uri"},
                },
                "bearer_methods_supported": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "scopes_supported": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "additionalProperties": False,
        },
        example={
            "resource": "http://test/mcp/oauth",
            "authorization_servers": [
                "http://test/.well-known/oauth-authorization-server?resource=http%3A%2F%2Ftest%2Fmcp%2Foauth"
            ],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp:read", "mcp:write"],
        },
    )
}

AUTHORIZATION_SERVER_METADATA_PARAMETERS = PROTECTED_RESOURCE_METADATA_PARAMETERS

AUTHORIZATION_SERVER_METADATA_RESPONSES = {
    200: json_response(
        description="Authorization server metadata document.",
        schema={
            "type": "object",
            "required": [
                "issuer",
                "authorization_endpoint",
                "token_endpoint",
                "registration_endpoint",
                "response_types_supported",
                "grant_types_supported",
                "token_endpoint_auth_methods_supported",
                "code_challenge_methods_supported",
                "scopes_supported",
            ],
            "properties": {
                "issuer": {"type": "string", "format": "uri"},
                "authorization_endpoint": {"type": "string", "format": "uri"},
                "device_authorization_endpoint": {"type": "string", "format": "uri"},
                "token_endpoint": {"type": "string", "format": "uri"},
                "registration_endpoint": {"type": "string", "format": "uri"},
                "response_types_supported": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "grant_types_supported": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "token_endpoint_auth_methods_supported": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "code_challenge_methods_supported": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "resource_indicators_supported": {"type": "boolean"},
                "scopes_supported": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "additionalProperties": True,
        },
        example={
            "issuer": "http://test",
            "authorization_endpoint": "http://test/oauth/authorize",
            "device_authorization_endpoint": "http://test/oauth/device/authorize",
            "token_endpoint": "http://test/oauth/token",
            "registration_endpoint": "http://test/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "resource_indicators_supported": True,
            "scopes_supported": ["mcp:read", "mcp:write"],
        },
    )
}
