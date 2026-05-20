"""FastAPI application for MCP Auth Test Server."""

from fastapi import FastAPI

from mcp_auth_test_server.mcp.no_auth import router as no_auth_router

app = FastAPI(
    title="MCP Auth Test Server",
    description="Test endpoints for MCP authentication schemes",
    version="0.1.0",
)

app.include_router(no_auth_router)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}
