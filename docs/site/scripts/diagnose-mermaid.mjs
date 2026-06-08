// Playwright script to diagnose Mermaid rendering issues
import { chromium } from 'playwright';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const browser = await chromium.launch({ headless: true });

for (const pagePath of ['/']) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  
  page.on('console', msg => {
    const text = msg.text();
    if (text.includes('mermaid') || text.includes('Mermaid') || text.includes('render') || msg.type() === 'error') {
      console.log(`  [${msg.type()}] ${text}`);
    }
  });
  
  page.on('pageerror', err => {
    console.log(`  [PAGE_ERROR] ${err.message}`);
  });
  
  const url = `http://127.0.0.1:4173${pagePath}`;
  console.log(`\n=== ${url} ===`);
  
  await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });
  
  // Wait for mermaid CDN to load
  await page.waitForFunction(() => typeof window.mermaid !== 'undefined', { timeout: 10000 });
  console.log("  Mermaid global loaded");
  
  // Wait longer for async render
  await page.waitForTimeout(3000);
  
  const result = await page.evaluate(() => {
    return {
      mermaidGlobal: typeof window.mermaid !== 'undefined',
      mermaidVersion: window.mermaid?.version || 'unknown',
      codeBlocks: document.querySelectorAll('code.language-mermaid').length,
      preBlocks: document.querySelectorAll('pre.language-mermaid').length,
      mermaidWrappers: document.querySelectorAll('.mermaid-render').length,
      mermaidSvgs: document.querySelectorAll('.mermaid-render svg').length,
      bodyHtml: document.querySelector('.content')?.innerHTML?.substring(0, 500),
    };
  });
  
  console.log(`  Diagnostics: ${JSON.stringify(result, null, 2)}`);
  
  await ctx.close();
}

await browser.close();
