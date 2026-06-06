# Deployment

This repo has two deployment surfaces:

- the FastAPI application, which is intended for local or custom hosting
- the static docs website under `docs/site`, which is deployed to GitHub Pages

## GitHub Pages docs site

The docs site is a separate SvelteKit + mdsvex project in `docs/site/`.

### Workflow

GitHub Pages deployment is handled by:

- `.github/workflows/deploy-docs.yml`

The workflow:

1. checks out the repo
2. installs Node.js
3. runs `npm ci` in `docs/site`
4. builds the static site with `BASE_PATH=/<repo-name>`
5. uploads `docs/site/build`
6. deploys the artifact with `actions/deploy-pages`

### Required repository settings

In GitHub repository settings:

1. open `Settings > Pages`
2. set the source to `GitHub Actions`

Without that setting, the workflow can build successfully but not publish the
site.

### Local verification

```bash
cd docs/site
npm install
npm run check
npm run build
```

### Base-path behavior

The docs site uses SvelteKit `paths.base` with `BASE_PATH` for production
builds. This is required for project Pages URLs such as:

```text
https://<owner>.github.io/<repo-name>/
```

## FastAPI app

The server itself is not deployed by the GitHub Pages workflow.

Run it locally with:

```bash
uv run uvicorn mcp_auth_test_server.app:app --reload --port 8765
```
