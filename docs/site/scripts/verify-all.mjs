// Verify all pages render correctly
import { chromium } from 'playwright';
import path from 'path';

const browser = await chromium.launch({ headless: true });

for (const pagePath of ['/', '/flows/', '/reference/']) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  
  const errors = [];
  page.on('pageerror', err => errors.push(err.message));
  
  const url = `http://127.0.0.1:4173${pagePath}`;
  await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });
  await page.waitForFunction(() => typeof window.mermaid !== 'undefined', { timeout: 10000 });
  await page.waitForTimeout(3000);
  
  const result = await page.evaluate(() => ({
    svgCount: document.querySelectorAll('.mermaid-render svg').length,
    errors: [],
  }));
  
  console.log(`${url} → SVGs: ${result.svgCount}, Errors: ${errors.length} ${errors.length ? errors.join('; ') : ''}`);
  await ctx.close();
}

await browser.close();
