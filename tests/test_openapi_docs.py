"""Tests for OpenAPI spec and documentation UIs."""

import pytest


@pytest.mark.asyncio
async def test_openapi_spec_is_available(client):
    response = await client.get("/openapi.json")

    assert response.status_code == 200
    data = response.json()
    assert data["openapi"].startswith("3.")
    assert "/health" in data["paths"]
    assert "/mcp/no-auth" not in data["paths"]
    assert "/mcp/oauth" in data["paths"]
    assert "/test-auth/bearer-token/mint" in data["paths"]
    assert "/mcp/oauth-v21" not in data["paths"]

    authorize_parameters = data["paths"]["/oauth/authorize"]["get"]["parameters"]
    redirect_uri_parameter = next(
        parameter for parameter in authorize_parameters if parameter["name"] == "redirect_uri"
    )
    resource_parameter = next(
        parameter for parameter in authorize_parameters if parameter["name"] == "resource"
    )
    code_challenge_parameter = next(
        parameter for parameter in authorize_parameters if parameter["name"] == "code_challenge"
    )
    assert "/docs/oauth-callback" in redirect_uri_parameter["description"]
    assert resource_parameter["required"] is True
    assert code_challenge_parameter["example"] == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGqstwM5lM"

    authorize_redirect_response = data["paths"]["/oauth/authorize"]["get"]["responses"]["302"]
    assert "/docs/oauth-callback" in authorize_redirect_response["description"]

    token_examples = data["paths"]["/oauth/token"]["post"]["requestBody"]["content"][
        "application/x-www-form-urlencoded"
    ]["examples"]
    assert token_examples["clientCredentials"]["value"] == {
        "grant_type": "client_credentials",
        "client_id": "phase-6-service-client",
        "client_secret": "phase-6-service-secret",
        "scope": "mcp:read",
    }
    assert token_examples["deviceCode"]["value"]["grant_type"] == (
        "urn:ietf:params:oauth:grant-type:device_code"
    )

    registration_examples = data["paths"]["/oauth/register"]["post"]["requestBody"]["content"][
        "application/json"
    ]["examples"]
    assert registration_examples["publicClient"]["value"]["grant_types"] == [
        "authorization_code",
        "refresh_token",
    ]

    assert data["paths"]["/health"]["get"]["tags"] == ["Health"]
    assert data["paths"]["/mcp/oauth"]["post"]["tags"] == ["MCP Endpoints"]
    assert data["paths"]["/mcp/bearer-token"]["post"]["tags"] == ["MCP Endpoints"]
    assert data["paths"]["/test-auth/bearer-token/mint"]["post"]["tags"] == ["Auth: Bearer Token"]
    assert data["paths"]["/oauth/token"]["post"]["tags"] == ["Auth: OAuth"]
    assert data["paths"]["/oauth/register"]["post"]["tags"] == ["Auth: OAuth"]
    assert data["paths"]["/.well-known/oauth-authorization-server"]["get"]["tags"] == ["Discovery"]

    tag_names = [tag["name"] for tag in data["tags"]]
    assert tag_names == [
        "Health",
        "MCP Endpoints",
        "Auth: Bearer Token",
        "Auth: OAuth",
        "Discovery",
    ]


@pytest.mark.asyncio
async def test_swagger_ui_is_available(client):
    response = await client.get("/docs")

    assert response.status_code == 200
    assert "Swagger UI" in response.text
    assert "/openapi.json" in response.text
    assert "/docs/oauth-callback" in response.text
    assert "OAuth redirect tip" in response.text


@pytest.mark.asyncio
async def test_oauth_callback_inspector_is_available(client):
    response = await client.get("/docs/oauth-callback?code=test-code&state=test-state")

    assert response.status_code == 200
    assert "OAuth Redirect Inspector" in response.text
    assert "test-code" in response.text
    assert "test-state" in response.text


@pytest.mark.asyncio
async def test_redoc_ui_is_available(client):
    response = await client.get("/redoc")

    assert response.status_code == 200
    assert "<redoc" in response.text
    assert "/openapi.json" in response.text
