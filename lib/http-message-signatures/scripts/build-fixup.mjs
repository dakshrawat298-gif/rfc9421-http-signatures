// Writes per-directory package.json markers so Node resolves the dual build
// correctly: dist/esm as ES modules and dist/cjs as CommonJS. Zero runtime
// dependencies; this only runs at build time.
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(here, "..", "dist");

const targets = [
  { dir: resolve(dist, "esm"), type: "module" },
  { dir: resolve(dist, "cjs"), type: "commonjs" },
];

for (const { dir, type } of targets) {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(resolve(dir, "package.json"), `${JSON.stringify({ type }, null, 2)}\n`);
}

console.log("build-fixup: wrote dist/esm and dist/cjs package.json type markers");
