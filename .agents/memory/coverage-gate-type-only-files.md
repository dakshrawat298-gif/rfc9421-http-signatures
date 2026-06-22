---
name: Coverage gate vs type-only files (tsx)
description: Why type-only TS files wreck a node --experimental-test-coverage gate and how to scope it
---

# Coverage gate with node --experimental-test-coverage (run via tsx)

**Type-only files report near-0% line coverage.** A file that is purely
`interface`/`type` declarations (e.g. a `types.ts`) compiles to no executable
JS, so the coverage tool counts its source lines as uncovered (~14% line). Left
in the aggregate it drags "all files" far below any realistic gate.

**Line/branch *line numbers* in the report are imprecise under tsx** (sourcemap
mapping). Lines that obviously always execute (e.g. an unconditional `return`)
can show as "uncovered". Judge by the **percentages**, not the listed line
numbers.

**How to apply (this lib's gate):**
- Scope the gate to executable `src/` only: repeat `--test-coverage-exclude` for
  `src/types.ts` and for `test/**` (excluding tests also stops test helpers from
  inflating/deflating the aggregate).
- Thresholds are percentages: `--test-coverage-lines=95` means 95% (`0.95` is
  effectively no gate). Branch coverage realistically floors lower than line
  coverage because of defensive branches, so the gate here is line/function 95,
  branch 90.

**Why:** without the excludes the gate fails at ~89% purely because of the
type-only file, even though every executable file is ≥97% line.
