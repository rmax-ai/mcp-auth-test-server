"""FastAPI application for MCP Auth Test Server."""

from fastapi import FastAPI

from mcp_auth_test_server.discovery.auth_server_metadata import (
    router as auth_server_metadata_router,
)
from mcp_auth_test_server.discovery.protected_resource import (
    router as protected_resource_router,
)
from mcp_auth_test_server.mcp.bearer_token import router as bearer_token_router
from mcp_auth_test_server.mcp.no_auth import router as no_auth_router

app = FastAPI(
    title="MCP Auth Test Server",
    description="Test endpoints for MCP authentication schemes",
    version="0.1.0",
)

app.include_router(no_auth_router)
app.include_router(bearer_token_router)
app.include_router(protected_resource_router)
app.include_router(auth_server_metadata_router)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}
