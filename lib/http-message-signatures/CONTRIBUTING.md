# Contributing

Thanks for your interest in contributing. This is a security-sensitive library,
so correctness and a disciplined, test-first process matter more than speed.

## Prerequisites

- Node.js >= 18
- [pnpm](https://pnpm.io/)

## Getting started

```sh
pnpm install
pnpm typecheck             # strict type-check of src, tests, and scripts
pnpm test                  # run the full test suite
pnpm test:coverage:check   # enforce the coverage gate over src/
pnpm validate:fixtures     # verify the RFC 9421 Appendix B fixtures
```

## Test-first (TDD) workflow

This project is built test-first. When adding a feature or fixing a bug, add or
extend a test that captures the desired behavior, then make it pass:

1. The RFC 9421 Appendix B fixtures are encoded under `test/fixtures/` and are
   independently validated against the published RFC keys by
   `scripts/validate-fixtures.ts`. **Fixtures are ground truth — do not edit a
   fixture to make a test pass.**
2. Behavior is specified by tests, with a dedicated suite per RFC area
   (`*.spec.test.ts`). New behavior must come with new or extended tests.
3. Coverage is gated in CI (>= 95% line/function, >= 90% branch over `src/`).
   Keep new code covered; do not weaken existing specs to pass.

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
- [ ] `pnpm test` passes
- [ ] `pnpm test:coverage:check` passes (coverage gate)
- [ ] `pnpm validate:fixtures` passes
- [ ] New behavior is covered by tests
- [ ] No new runtime dependencies were added

## Reporting security issues

Do not file security vulnerabilities as public issues — see
[SECURITY.md](./SECURITY.md) for the private reporting process.
