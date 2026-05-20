"""Pytest fixtures for MCP Auth Test Server tests."""

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from mcp_auth_test_server.app import app


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as test_client:
        yield test_client
