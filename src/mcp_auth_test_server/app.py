"""FastAPI application for MCP Auth Test Server."""

from fastapi import FastAPI

app = FastAPI(
    title="MCP Auth Test Server",
    description="Test endpoints for MCP authentication schemes",
    version="0.1.0",
)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}
