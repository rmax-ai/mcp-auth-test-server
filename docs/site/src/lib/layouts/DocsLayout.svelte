<script>
  import { base } from "$app/paths";

  export let title = "MCP Auth Test Server";
  export let description =
    "A test server and CLI for exercising bearer, OAuth auth-code, device, and client-credentials flows for MCP resources.";

  const navItems = [
    { href: `${base}/`, label: "Overview" },
    { href: `${base}/flows/`, label: "Flows" },
    { href: `${base}/reference/`, label: "Reference" },
  ];
</script>

<svelte:head>
  <title>{title} | MCP Auth Test Server</title>
  <meta name="description" content={description} />
</svelte:head>

<div class="page-shell">
  <div class="backdrop backdrop-a"></div>
  <div class="backdrop backdrop-b"></div>

  <header class="site-header">
    <a class="brand" href={`${base}/`}>
      <span class="brand-mark">MCP</span>
      <span class="brand-copy">
        <strong>MCP Auth Test Server</strong>
        <small>Spec-focused auth surfaces and a generic client CLI</small>
      </span>
    </a>

    <nav aria-label="Primary">
      {#each navItems as item}
        <a href={item.href}>{item.label}</a>
      {/each}
      <a href="https://github.com/rmax-ai/mcp-auth-test-server" rel="noreferrer">GitHub</a>
    </nav>
  </header>

  <main class="content">
    <slot />
  </main>

  <footer class="site-footer">
    <p>Built with SvelteKit + mdsvex. Deployable as a static site on GitHub Pages.</p>
  </footer>
</div>

<style>
  :global(html) {
    background:
      radial-gradient(circle at top left, rgba(255, 164, 27, 0.18), transparent 30%),
      radial-gradient(circle at 85% 20%, rgba(54, 158, 255, 0.18), transparent 28%),
      linear-gradient(180deg, #f7f5ef 0%, #f4efe4 42%, #efe8d8 100%);
    color: #1b1710;
    font-family:
      "Iowan Old Style",
      "Palatino Linotype",
      "Book Antiqua",
      Georgia,
      serif;
  }

  :global(body) {
    margin: 0;
    min-height: 100vh;
  }

  :global(*) {
    box-sizing: border-box;
  }

  :global(a) {
    color: inherit;
  }

  :global(code) {
    font-family:
      "SFMono-Regular",
      Consolas,
      "Liberation Mono",
      Menlo,
      monospace;
  }

  :global(pre) {
    overflow-x: auto;
    padding: 1.1rem 1.25rem;
    border-radius: 18px;
    background: #17140f;
    color: #f8f3e8;
    border: 1px solid rgba(38, 31, 21, 0.2);
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
  }

  :global(pre code) {
    display: block;
    line-height: 1.6;
    font-size: 0.93rem;
  }

  :global(h1),
  :global(h2),
  :global(h3) {
    font-family:
      "Avenir Next Condensed",
      "Arial Narrow",
      sans-serif;
    letter-spacing: 0.02em;
    line-height: 0.95;
    margin: 0 0 0.75rem;
  }

  :global(h1) {
    font-size: clamp(3.4rem, 9vw, 6.8rem);
  }

  :global(h2) {
    font-size: clamp(2rem, 3.8vw, 3rem);
    margin-top: 2.75rem;
  }

  :global(h3) {
    font-size: clamp(1.35rem, 2.5vw, 1.9rem);
    margin-top: 1.75rem;
  }

  :global(p),
  :global(li) {
    font-size: 1.03rem;
    line-height: 1.7;
  }

  :global(table) {
    width: 100%;
    border-collapse: collapse;
    margin: 1.5rem 0;
    background: rgba(255, 252, 246, 0.72);
    border-radius: 16px;
    overflow: hidden;
    backdrop-filter: blur(10px);
  }

  :global(th),
  :global(td) {
    text-align: left;
    padding: 0.9rem 1rem;
    border-bottom: 1px solid rgba(48, 38, 24, 0.08);
    vertical-align: top;
  }

  :global(blockquote) {
    margin: 1.5rem 0;
    padding: 0.25rem 0 0.25rem 1rem;
    border-left: 4px solid #e17d22;
    color: #463a2c;
  }

  :global(.eyebrow) {
    display: inline-flex;
    gap: 0.55rem;
    align-items: center;
    padding: 0.4rem 0.72rem;
    border-radius: 999px;
    background: rgba(255, 249, 239, 0.84);
    border: 1px solid rgba(80, 63, 39, 0.12);
    font-family:
      "Avenir Next",
      "Segoe UI",
      sans-serif;
    font-size: 0.76rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
  }

  :global(.panel-grid) {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1rem;
    margin: 1.5rem 0 2rem;
  }

  :global(.panel-card) {
    padding: 1.2rem;
    border-radius: 20px;
    background: rgba(255, 251, 244, 0.8);
    border: 1px solid rgba(78, 59, 34, 0.12);
    box-shadow: 0 20px 45px rgba(68, 51, 29, 0.08);
  }

  :global(.hero-note) {
    max-width: 55rem;
    font-size: 1.16rem;
    color: #3a3025;
  }

  :global(.command-callout) {
    margin: 1.5rem 0;
    padding: 1rem 1.15rem;
    border-radius: 18px;
    border: 1px solid rgba(62, 47, 27, 0.1);
    background: rgba(255, 252, 247, 0.75);
  }

  .page-shell {
    position: relative;
    min-height: 100vh;
    overflow: hidden;
  }

  .backdrop {
    position: fixed;
    inset: auto;
    border-radius: 999px;
    filter: blur(30px);
    opacity: 0.9;
    pointer-events: none;
  }

  .backdrop-a {
    width: 16rem;
    height: 16rem;
    top: 6rem;
    right: -3rem;
    background: rgba(255, 178, 82, 0.22);
  }

  .backdrop-b {
    width: 18rem;
    height: 18rem;
    bottom: 6rem;
    left: -5rem;
    background: rgba(92, 164, 255, 0.18);
  }

  .site-header,
  .content,
  .site-footer {
    position: relative;
    z-index: 1;
    width: min(1100px, calc(100vw - 2rem));
    margin: 0 auto;
  }

  .site-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1.5rem;
    padding: 1.25rem 0 0;
  }

  .brand {
    display: inline-flex;
    gap: 0.9rem;
    align-items: center;
    text-decoration: none;
  }

  .brand-mark {
    display: grid;
    place-items: center;
    width: 3rem;
    height: 3rem;
    border-radius: 18px;
    background: linear-gradient(135deg, #1a1711, #4a3620);
    color: #f7efe3;
    font-family:
      "Avenir Next Condensed",
      "Arial Narrow",
      sans-serif;
    font-weight: 800;
    letter-spacing: 0.1em;
  }

  .brand-copy {
    display: grid;
  }

  .brand-copy strong {
    font-family:
      "Avenir Next Condensed",
      "Arial Narrow",
      sans-serif;
    font-size: 1.12rem;
    letter-spacing: 0.04em;
  }

  .brand-copy small {
    color: #5b4b39;
  }

  nav {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    align-items: center;
  }

  nav a {
    text-decoration: none;
    padding: 0.55rem 0.85rem;
    border-radius: 999px;
    background: rgba(255, 252, 247, 0.76);
    border: 1px solid rgba(76, 58, 33, 0.08);
  }

  .content {
    padding: 3.2rem 0 4rem;
  }

  .site-footer {
    padding: 0 0 2.5rem;
    color: #5f513e;
  }

  @media (max-width: 720px) {
    .site-header {
      align-items: flex-start;
      flex-direction: column;
    }

    .content {
      padding-top: 2.2rem;
    }
  }
</style>
