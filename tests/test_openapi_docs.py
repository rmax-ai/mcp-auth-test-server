"""Tests for OpenAPI spec and documentation UIs."""

import pytest


@pytest.mark.asyncio
async def test_openapi_spec_is_available(client):
    response = await client.get("/openapi.json")

    assert response.status_code == 200
    data = response.json()
    assert data["openapi"].startswith("3.")
    assert "/health" in data["paths"]
    assert "/mcp/no-auth" in data["paths"]

    mcp_examples = data["paths"]["/mcp/no-auth"]["post"]["requestBody"]["content"][
        "application/json"
    ]["examples"]
    assert mcp_examples["echoTool"]["value"]["params"]["name"] == "echo"
    assert mcp_examples["echoTool"]["value"]["params"]["arguments"]["message"] == "hello from docs"

    authorize_parameters = data["paths"]["/oauth/authorize"]["get"]["parameters"]
    code_challenge_parameter = next(
        parameter for parameter in authorize_parameters if parameter["name"] == "code_challenge"
    )
    assert code_challenge_parameter["example"] == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGqstwM5lM"

    token_examples = data["paths"]["/oauth/token"]["post"]["requestBody"]["content"][
        "application/x-www-form-urlencoded"
    ]["examples"]
    assert token_examples["clientCredentials"]["value"] == {
        "grant_type": "client_credentials",
        "client_id": "phase-6-service-client",
        "client_secret": "phase-6-service-secret",
        "scope": "mcp:read",
    }

    registration_examples = data["paths"]["/oauth/register"]["post"]["requestBody"]["content"][
        "application/json"
    ]["examples"]
    assert registration_examples["publicClient"]["value"]["grant_types"] == [
        "authorization_code",
        "refresh_token",
    ]

    assert data["paths"]["/health"]["get"]["tags"] == ["Health"]
    assert data["paths"]["/mcp/no-auth"]["post"]["tags"] == ["MCP: No Auth"]
    assert data["paths"]["/oauth/token"]["post"]["tags"] == ["OAuth 2.0: Auth Code + PKCE"]
    assert data["paths"]["/.well-known/oauth-authorization-server"]["get"]["tags"] == ["Discovery"]

    tag_names = [tag["name"] for tag in data["tags"]]
    assert tag_names == [
        "Health",
        "MCP: No Auth",
        "MCP: Bearer Token",
        "OAuth 2.0: Client Credentials",
        "OAuth 2.0: Auth Code + PKCE",
        "OAuth 2.1",
        "Dynamic Client Registration",
        "Discovery",
    ]


@pytest.mark.asyncio
async def test_swagger_ui_is_available(client):
    response = await client.get("/docs")

    assert response.status_code == 200
    assert "Swagger UI" in response.text
    assert "/openapi.json" in response.text


@pytest.mark.asyncio
async def test_redoc_ui_is_available(client):
    response = await client.get("/redoc")

    assert response.status_code == 200
    assert "<redoc" in response.text
    assert "/openapi.json" in response.text
