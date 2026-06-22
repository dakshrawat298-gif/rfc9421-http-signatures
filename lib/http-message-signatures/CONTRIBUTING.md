# Contributing

Thanks for your interest in contributing. This is a security-sensitive library,
so correctness and a disciplined, test-first process matter more than speed.

## Prerequisites

- Node.js >= 18
- [pnpm](https://pnpm.io/)

## Getting started

```sh
pnpm install
pnpm typecheck          # strict type-check of src, tests, and scripts
pnpm test               # run the full test suite
pnpm validate:fixtures  # verify the RFC 9421 Appendix B fixtures
```

## Test-first (TDD) workflow

This project is built strictly test-first. The expectation is **red → green**:

1. The RFC 9421 Appendix B fixtures are encoded under `test/fixtures/` and are
   independently validated against the published RFC keys by
   `scripts/validate-fixtures.ts`. **Fixtures are ground truth — do not edit a
   fixture to make a test pass.**
2. Behavior is specified by failing tests *before* the implementation exists.
   Each RFC area has a dedicated suite (`*.spec.test.ts`).
3. Implementation is then added layer by layer to turn suites green, without
   weakening the specs.

When adding a feature or fixing a bug, add or extend a failing test first, then
make it pass.

## Coding standards

- Strict TypeScript. Code must pass `pnpm typecheck` with no errors.
- Zero runtime dependencies. Do not add a runtime dependency without explicit
  maintainer approval — it undermines a core guarantee of this library.
- No insecure defaults. Never introduce a default algorithm, silent downgrade,
  or ambient default key.
- All cryptography goes through the Web Crypto API (`crypto.subtle`).

## Commits and releases

- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit
  messages (e.g. `feat:`, `fix:`, `test:`, `docs:`, `chore:`).
- The project follows [semantic versioning](https://semver.org/).
- User-facing changes should include a changeset describing the change.

## Pull requests

Before opening a PR, ensure:

- [ ] `pnpm typecheck` passes
- [ ] `pnpm test` passes (or new specs are intentionally red and clearly noted)
- [ ] `pnpm validate:fixtures` passes
- [ ] New behavior is covered by tests
- [ ] No new runtime dependencies were added

## Reporting security issues

Do not file security vulnerabilities as public issues — see
[SECURITY.md](./SECURITY.md) for the private reporting process.
