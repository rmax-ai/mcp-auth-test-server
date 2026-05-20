"""Pytest fixtures for MCP Auth Test Server tests."""

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from mcp_auth_test_server.app import app
from mcp_auth_test_server.auth.token_store import oauth_token_store


@pytest_asyncio.fixture(autouse=True)
async def reset_oauth_state():
    oauth_token_store.reset()
    yield
    oauth_token_store.reset()


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as test_client:
        test_client.app_state = {"oauth_token_store": oauth_token_store}
        yield test_client
