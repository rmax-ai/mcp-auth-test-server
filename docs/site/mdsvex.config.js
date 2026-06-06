import { fileURLToPath } from "node:url";

import { defineMDSveXConfig } from "mdsvex";

const docsLayoutPath = fileURLToPath(
  new URL("./src/lib/layouts/DocsLayout.svelte", import.meta.url),
);

export default defineMDSveXConfig({
  extensions: [".svx", ".md"],
  smartypants: true,
  layout: {
    _: docsLayoutPath,
  },
});
