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
