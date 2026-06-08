// Playwright script to check Mermaid rendering on the docs site
import { chromium } from 'playwright';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const siteDir = path.resolve(__dirname, '..');

const pages = ['/', '/flows/', '/reference/'];
let totalErrors = 0;

for (const pagePath of pages) {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  
  const consoleErrors = [];
  
  page.on('console', msg => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
    }
  });
  
  page.on('pageerror', err => {
    consoleErrors.push(`PAGE ERROR: ${err.message}`);
  });
  
  const url = `http://127.0.0.1:4173${pagePath}`;
  console.log(`\n=== ${url} ===`);
  
  await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });
  
  // Wait a bit for Mermaid to render
  await page.waitForTimeout(3000);
  
  // Check for Mermaid SVGs
  const mermaidSvgs = await page.evaluate(() => {
    return document.querySelectorAll('.mermaid svg, pre.language-mermaid + .mermaid, svg.mermaid').length;
  });
  
  const mermaidPreBlocks = await page.evaluate(() => {
    return document.querySelectorAll('pre.language-mermaid').length;
  });
  
  console.log(`  Pre blocks (unrendered): ${mermaidPreBlocks}`);
  console.log(`  Mermaid SVGs (rendered): ${mermaidSvgs}`);
  
  if (consoleErrors.length > 0) {
    console.log(`  Console errors (${consoleErrors.length}):`);
    for (const err of consoleErrors) {
      console.log(`    ${err}`);
      totalErrors++;
    }
  } else {
    console.log('  No console errors');
  }
  
  // Check if Mermaid loaded
  const mermaidLoaded = await page.evaluate(() => {
    return typeof window.mermaid !== 'undefined' || document.querySelector('script[src*="mermaid"]') !== null;
  });
  console.log(`  Mermaid CDN script loaded: ${mermaidLoaded}`);
  
  // List all scripts on the page
  const scripts = await page.evaluate(() => {
    return Array.from(document.scripts).map(s => s.src || s.type || 'inline').slice(0, 10);
  });
  console.log(`  Scripts: ${JSON.stringify(scripts)}`);
  
  await browser.close();
}

if (totalErrors > 0) {
  console.log(`\n✗ ${totalErrors} total console errors`);
  process.exit(1);
} else {
  console.log('\n✓ No errors found');
}
