"""FastAPI application for MCP Auth Test Server."""

from html import escape

from fastapi import FastAPI, Request
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.responses import HTMLResponse

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
from mcp_auth_test_server.mcp.oauth_v2_3l import router as oauth_v2_3l_router
from mcp_auth_test_server.openapi_examples import HEALTH_RESPONSES

OPENAPI_TAGS = [
    {
        "name": "Health",
        "description": "Service health and version information.",
    },
    {
        "name": "MCP Endpoints",
        "description": "Protected MCP JSON-RPC endpoints exposed by the service.",
    },
    {
        "name": "Auth: Bearer Token",
        "description": "Static bearer-token auth helpers and test token minting.",
    },
    {
        "name": "Auth: OAuth",
        "description": (
            "Shared OAuth authorization server endpoints supporting "
            "authorization code + PKCE, client credentials, and device flow."
        ),
    },
    {
        "name": "Discovery",
        "description": "OAuth authorization server and protected resource discovery endpoints.",
    },
]

MINTED_BEARER_SECURITY = "MintedBearerToken"
DOCS_REDIRECT_INSPECTOR_PATH = "/docs/oauth-callback"

DOCS_OAUTH_HELP_BANNER = f"""
<section
  data-docs-oauth-helper
  style="
    margin: 16px 0;
    padding: 16px;
    border: 1px solid #d7dde5;
    border-radius: 8px;
    background: #f7fafc;
    color: #1f2937;
  "
>
  <strong>OAuth redirect tip</strong>
  <p style="margin: 8px 0 0;">
    Swagger UI cannot reliably show cross-origin redirect targets for the mock
    authorize endpoints because the browser follows the <code>302</code>
    before the UI can render it. For manual testing in the docs, use a
    same-origin redirect URI that points at
    <a
      href="{DOCS_REDIRECT_INSPECTOR_PATH}"
      target="_blank"
      rel="noreferrer"
    ><code>{DOCS_REDIRECT_INSPECTOR_PATH}</code></a>.
  </p>
  <p style="margin: 8px 0 0;">
    Example: <code id="oauth-callback-example">{DOCS_REDIRECT_INSPECTOR_PATH}</code>
  </p>
</section>
<script>
window.addEventListener("load", () => {{
  const example = document.getElementById("oauth-callback-example");
  if (example) {{
    example.textContent = `${{window.location.origin}}{DOCS_REDIRECT_INSPECTOR_PATH}`;
  }}
  const uiContainer = document.querySelector(".swagger-ui .information-container.wrapper");
  const banner = document.querySelector("[data-docs-oauth-helper]");
  if (uiContainer && banner) {{
    uiContainer.insertAdjacentElement("afterend", banner);
  }}
}});
</script>
""".strip()


DOCS_REDIRECT_INSPECTOR_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>OAuth Redirect Inspector</title>
    <style>
      body {
        font-family: sans-serif;
        line-height: 1.5;
        margin: 2rem auto;
        max-width: 52rem;
        padding: 0 1rem;
        color: #1f2937;
      }
      code, pre {
        font-family: ui-monospace, SFMono-Regular, SFMono-Regular, Menlo, monospace;
      }
      .panel {
        background: #f7fafc;
        border: 1px solid #d7dde5;
        border-radius: 8px;
        padding: 1rem;
        margin-top: 1rem;
      }
      dt {
        font-weight: 600;
        margin-top: 0.75rem;
      }
      dd {
        margin-left: 0;
      }
      pre {
        background: #111827;
        border-radius: 8px;
        color: #f9fafb;
        overflow-x: auto;
        padding: 1rem;
      }
    </style>
  </head>
  <body>
    <h1>OAuth Redirect Inspector</h1>
    <p>
      Use this page as the <code>redirect_uri</code> when testing authorize
      endpoints from Swagger UI. Because the callback stays on the same origin,
      the browser can render the final redirect here and show the returned
      query parameters.
    </p>
    <div class="panel">
      <p><strong>Suggested redirect URI</strong></p>
      <pre id="redirect-uri">__REDIRECT_URI__</pre>
    </div>
    <div class="panel">
      <p><strong>Observed redirect parameters</strong></p>
      __EMPTY_STATE__
      <dl id="params">__PARAMS_MARKUP__</dl>
    </div>
    <div class="panel">
      <p><strong>Full URL</strong></p>
      <pre id="full-url">__FULL_URL__</pre>
    </div>
    <script>
      const url = new URL(window.location.href);
      const redirectUri = document.getElementById("redirect-uri");
      const fullUrl = document.getElementById("full-url");
      const paramsRoot = document.getElementById("params");
      const emptyState = document.getElementById("empty-state");

      redirectUri.textContent = `${window.location.origin}${url.pathname}`;
      fullUrl.textContent = window.location.href;

      const params = Array.from(url.searchParams.entries());
      if (params.length > 0 && paramsRoot.children.length === 0) {
        if (emptyState) {
          emptyState.remove();
        }
        for (const [name, value] of params) {
          const dt = document.createElement("dt");
          dt.textContent = name;
          const dd = document.createElement("dd");
          const code = document.createElement("code");
          code.textContent = value;
          dd.appendChild(code);
          paramsRoot.appendChild(dt);
          paramsRoot.appendChild(dd);
        }
      }
    </script>
  </body>
</html>
""".strip()


def _docs_redirect_params_markup(request: Request) -> str:
    items = list(request.query_params.multi_items())
    if not items:
        return ""
    return "".join(
        f"<dt>{escape(name)}</dt><dd><code>{escape(value)}</code></dd>"
        for name, value in items
    )

app = FastAPI(
    title="MCP Auth Test Server",
    description="Test endpoints for MCP authentication schemes",
    version="0.1.0",
    openapi_url="/openapi.json",
    docs_url=None,
    redoc_url=None,
    openapi_tags=OPENAPI_TAGS,
)


def _custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
    )
    if "components" not in schema:
        schema["components"] = {}
    schema["components"]["securitySchemes"] = {
        MINTED_BEARER_SECURITY: {
            "type": "http",
            "scheme": "bearer",
            "description": (
                "Mint a temporary token via POST /test-auth/bearer-token/mint, "
                "then paste the access_token value here. "
                "The static token `test-bearer-token` also works."
            ),
        },
    }
    app.openapi_schema = schema
    return schema


app.openapi = _custom_openapi

app.include_router(bearer_token_router)
app.include_router(oauth_v2_3l_router)
app.include_router(dynamic_registration_router)
app.include_router(protected_resource_router)
app.include_router(auth_server_metadata_router)


@app.get("/health", responses=HEALTH_RESPONSES, tags=["Health"])
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    swagger_ui = get_swagger_ui_html(
        openapi_url=app.openapi_url or "/openapi.json",
        title=f"{app.title} - Swagger UI",
    )
    body = swagger_ui.body.decode("utf-8").replace("</body>", f"{DOCS_OAUTH_HELP_BANNER}</body>")
    headers = {
        key: value
        for key, value in swagger_ui.headers.items()
        if key.lower() not in {"content-length", "content-type"}
    }
    return HTMLResponse(body, status_code=swagger_ui.status_code, headers=headers)


@app.get(DOCS_REDIRECT_INSPECTOR_PATH, include_in_schema=False)
async def docs_oauth_callback(request: Request):
    redirect_uri = escape(str(request.url.replace(query=None)))
    params_markup = _docs_redirect_params_markup(request)
    empty_state = ""
    if not params_markup:
        empty_state = '<div id="empty-state">No query parameters were provided yet.</div>'
    html = (
        DOCS_REDIRECT_INSPECTOR_TEMPLATE.replace("__REDIRECT_URI__", redirect_uri)
        .replace("__EMPTY_STATE__", empty_state)
        .replace("__PARAMS_MARKUP__", params_markup)
        .replace("__FULL_URL__", escape(str(request.url)))
    )
    return HTMLResponse(
        html
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
