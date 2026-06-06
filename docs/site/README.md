# Docs Site

This directory contains the static project website for `mcp-auth-test-server`.
It is a separate Node-based app built with:

- SvelteKit
- `@sveltejs/adapter-static`
- mdsvex

The site is intended for GitHub Pages deployment and is built independently of
the Python server package.

## Local development

```bash
npm install
npm run dev
```

## Validation

```bash
npm run check
npm run build
```

## Structure

- `src/routes/+page.svx` — landing page
- `src/routes/flows/+page.svx` — end-to-end auth flow walkthroughs
- `src/routes/reference/+page.svx` — endpoint and behavior reference
- `src/lib/layouts/DocsLayout.svelte` — shared mdsvex layout
- `mdsvex.config.js` — mdsvex configuration
- `svelte.config.js` — SvelteKit + adapter-static configuration
- `vite.config.js` — Vite configuration

## GitHub Pages

The repository workflow at `.github/workflows/deploy-docs.yml` builds this app
with:

```bash
BASE_PATH=/<repo-name> npm run build
```

That base path is required for project Pages URLs such as:

```text
https://<owner>.github.io/<repo-name>/
```
