"""FastAPI application for MCP Auth Test Server."""

from fastapi import FastAPI
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)

from mcp_auth_test_server.auth.dynamic_registration import (
    router as dynamic_registration_router,
)
from mcp_auth_test_server.discovery.auth_server_metadata import (
    router as auth_server_metadata_router,
)
from mcp_auth_test_server.discovery.protected_resource import (
    router as protected_resource_router,
)
from mcp_auth_test_server.mcp.bearer_token import router as bearer_token_router
from mcp_auth_test_server.mcp.no_auth import router as no_auth_router
from mcp_auth_test_server.mcp.oauth_v1 import router as oauth_v1_router
from mcp_auth_test_server.mcp.oauth_v2_2l import router as oauth_v2_2l_router
from mcp_auth_test_server.mcp.oauth_v2_3l import router as oauth_v2_3l_router
from mcp_auth_test_server.mcp.oauth_v21 import router as oauth_v21_router

app = FastAPI(
    title="MCP Auth Test Server",
    description="Test endpoints for MCP authentication schemes",
    version="0.1.0",
    openapi_url="/openapi.json",
    docs_url=None,
    redoc_url=None,
)

app.include_router(no_auth_router)
app.include_router(bearer_token_router)
app.include_router(oauth_v1_router)
app.include_router(oauth_v2_2l_router)
app.include_router(oauth_v2_3l_router)
app.include_router(oauth_v21_router)
app.include_router(dynamic_registration_router)
app.include_router(protected_resource_router)
app.include_router(auth_server_metadata_router)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url or "/openapi.json",
        title=f"{app.title} - Swagger UI",
    )


@app.get("/docs/oauth2-redirect", include_in_schema=False)
async def swagger_ui_redirect():
    return get_swagger_ui_oauth2_redirect_html()


@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    return get_redoc_html(
        openapi_url=app.openapi_url or "/openapi.json",
        title=f"{app.title} - ReDoc",
        with_google_fonts=False,
    )
