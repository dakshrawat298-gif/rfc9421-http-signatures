// Cross-version test runner. Node's built-in test runner only learned to
// expand glob patterns (e.g. "test/**/*.test.ts") in v21; on Node 18 and 20 the
// glob is treated as a literal path and the runner exits with
// "Could not find '.../test/**/*.test.ts'". To stay compatible across Node 18,
// 20, and 22 we discover the test files ourselves and pass them explicitly.
//
// Any arguments given to this script are forwarded verbatim as Node CLI flags
// before the file list (e.g. coverage flags), so the same runner backs the
// plain test, coverage, and coverage-gate scripts. Zero runtime dependencies.
import { readdirSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const testDir = resolve(here, "..", "test");

/** Recursively collect every *.test.ts file under `dir`. */
function collectTests(dir) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...collectTests(full));
    } else if (entry.isFile() && entry.name.endsWith(".test.ts")) {
      found.push(full);
    }
  }
  return found;
}

const passthrough = process.argv.slice(2);
const files = collectTests(testDir).sort();

if (files.length === 0) {
  console.error(`No *.test.ts files found under ${testDir}`);
  process.exit(1);
}

const args = ["--import", "tsx", "--test", ...passthrough, ...files];
const result = spawnSync(process.execPath, args, { stdio: "inherit" });

if (result.error) {
  console.error(result.error);
  process.exit(1);
}
process.exit(result.status ?? 1);
