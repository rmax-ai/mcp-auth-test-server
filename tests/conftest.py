"""Pytest fixtures for MCP Auth Test Server tests."""

from httpx import AsyncClient, ASGITransport
import pytest

from mcp_auth_test_server.app import app


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")
