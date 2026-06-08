// Validate all Mermaid diagrams in the docs
import mermaid from 'mermaid';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../../..');

mermaid.initialize({
  startOnLoad: false,
});

// Files containing mermaid diagrams
const files = [
  'README.md',
  'docs/auth-schemes.md',
  'docs/architecture.md',
  'docs/site/src/routes/+page.svx',
];

// Regex to extract mermaid code blocks
const MERMAID_RE = /```mermaid\n([\s\S]*?)```/g;

let allOk = true;

for (const relPath of files) {
  const fullPath = path.join(repoRoot, relPath);
  const content = fs.readFileSync(fullPath, 'utf-8');
  let match;
  let blockIdx = 0;

  while ((match = MERMAID_RE.exec(content)) !== null) {
    const diagramSource = match[1].trim();
    blockIdx++;
    
    // Attempt to parse
    try {
      const { diagramType, diagram } = await mermaid.parse(diagramSource);
      // parse() only throws on error, no return value needed
      console.log(`✓ ${relPath} (block ${blockIdx}) [${diagramType}] — OK`);
    } catch (err) {
      allOk = false;
      const lineOffset = content.substring(0, match.index).split('\n').length;
      console.error(`✗ ${relPath} (block ${blockIdx}, line ~${lineOffset})`);
      console.error(`  Error: ${err.message || err}`);
      console.error(`  First 200 chars: ${diagramSource.substring(0, 200)}`);
    }
  }
  
  if (blockIdx === 0) {
    console.log(`- ${relPath}: no mermaid blocks found`);
  }
}

process.exit(allOk ? 0 : 1);
