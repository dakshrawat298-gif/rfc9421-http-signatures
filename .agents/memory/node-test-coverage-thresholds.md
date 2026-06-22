---
name: Node test coverage thresholds are percentages
description: Units gotcha for node --test coverage threshold flags.
---

The Node built-in test runner coverage gate flags take a **percentage 0–100**,
not a 0–1 fraction:

- `--test-coverage-lines=95` enforces 95% line coverage.
- `--test-coverage-functions=95`, `--test-coverage-branches=95` likewise.

`0.95` means **0.95%** — effectively no gate (process exits 0 even at ~1%
coverage). Verified empirically on Node 24: a ~50%-covered file passes
`--test-coverage-functions=0.95` (exit 0) and fails `=95` (exit 1).

**How to apply:** when wiring a ">= 95%" coverage gate in CI, use `95`, never
`0.95`.

## Type-only modules tank global line coverage

`node --experimental-test-coverage` reports a **type-only** module (a file that
is all `interface`/`type` declarations, e.g. a `types.ts`) as mostly *uncovered*
— it lists nearly every line as uncovered and shows ~10–15% line coverage, even
though the emitted JS is effectively empty. This is a measurement artifact, not
real dead code, and it can drag global line% well below a per-logic-file target
(e.g. logic files at 94–100% but global ~84%).

**How to apply:** judge coverage on the logic modules, not the global number, or
exclude type-only files from the report. Do not chase a global ">=95%" by
gaming a pure-types file — it cannot be "covered" by tests.
