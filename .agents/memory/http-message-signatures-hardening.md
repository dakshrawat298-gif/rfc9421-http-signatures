---
name: http-message-signatures hardening decisions
description: Durable cross-runtime + strict-parsing decisions for the RFC 9421 http-message-signatures lib
---

# Cross-runtime WebCrypto resolution

The lib must run on browsers/Deno/edge/Node 18+. Resolve `SubtleCrypto` via an
async `getSubtle()` that **prefers `globalThis.crypto.subtle`** and only falls
back to `(await import("node:crypto")).webcrypto.subtle` when the global is
absent (Node 18 does not expose `globalThis.crypto` by default — it became an
unflagged global in Node 19).

**Why:** A static `import { webcrypto } from "node:crypto"` binds the runtime
and public types to Node, which breaks bundling for browser/edge consumers and
was flagged in review. Legacy `node:crypto` `createSign`/`createVerify` must
never be used — all primitives go through Web Crypto `SubtleCrypto`.

**How to apply:** Public `CryptoKey` type = `globalThis.CryptoKey` (this global
type *is* present under `@types/node` 25 with `lib: es2022`). BUT the algorithm
parameter types (`RsaPssParams`, `EcdsaParams`, `AlgorithmIdentifier`) are NOT
global there — define them as a structural union instead of importing the
`node:crypto` `webcrypto` namespace.

# Strict SFV parsing for signatures (duplicate keys)

Reject duplicate **dictionary keys** and duplicate **parameter keys** in the
SFV parser (hard-fail with `MalformedSignatureError`).

**Why:** RFC 8941's permissive default is last-value-wins, but in a
signature-verification context a repeated key is an ambiguity/cross-impl
mismatch risk. Strict rejection was an explicit hardening decision.

**How to apply:** RFC 9421 Appendix B fixtures contain no duplicate keys, so
this does not break the published vectors. If you ever relax this, you reopen
the parser-ambiguity attack surface.

# Policy input validation

`policy.clockTolerance` must be validated as a finite, non-negative number
(reject `NaN`/`Infinity`/negative with `RangeError`); default is `5` seconds.
Invalid tolerance silently distorts time checks otherwise.

# Trailer (`;tr`) components read a separate field map

A component carrying `;tr` MUST be canonicalized from a distinct trailer
section (`RequestLike.trailers` / `ResponseLike.trailers`), never from the
headers map. A `;tr` field absent from `trailers` (even if present in headers)
is "not present" and must throw.

**Why:** Treating `;tr` as a no-op alias for the header lookup is a
canonicalization/security gap — the signer's intent (trailer vs header) is part
of the signed component identifier and the two sections are semantically
different. Flagged in review.

**How to apply:** `;tr` and `;req` compose (`getSource` picks request-vs-self,
then the tr branch picks trailers-vs-headers). Appendix B vectors use no
trailers, so this doesn't touch published fixtures.

# Strict SFV serialization (no silent coercion)

The serializer must reject out-of-data-model values rather than coercing them:
`serializeDecimal` rejects >12 integer digits and anything not exactly
representable in ≤3 fractional digits (do NOT round); `serializeToken`
validates the RFC 8941 token grammar (ALPHA/`*` start, tchar/`:`/`/` rest).

**Why:** Silent rounding/coercion changes the canonical bytes that get signed,
producing signatures that don't match what the caller asked for — a correctness
and cross-impl risk. Parsing strictness without serialization strictness is a
half-measure flagged in review.

# Sign and verify must be symmetric: own the raw-key crypto on both sides

The sign path accepts a raw `CryptoKey` (+ explicit `alg`) and does the
WebCrypto work in-library. The verify path MUST offer the equivalent — a
library-owned `createVerifyingKey(key, alg)` factory — not just a
caller-supplied `VerifyingKey.verify()` callback.

**Why:** Delegating verification entirely to caller callbacks pushes
RFC-correctness (per-alg params, key usage, and especially ECDSA's IEEE P1363
`r||s` signature encoding that WebCrypto mandates) out of the library, where
each caller can silently get it wrong. An asymmetry where sign is library-owned
but verify is delegated was flagged as a compliance/reliability gap in review.
A single `CryptoKey` maps to exactly one registered algorithm, so the factory
binds `algs: [alg]`, which also preserves the §3.2 downgrade defense. Keep the
custom-`VerifyingKey` escape hatch for HSM/KMS backends.

# Library workflow lives at repo ROOT, package-filtered

The GitHub Actions workflow for a package in this pnpm monorepo must live at the
repo-root `.github/workflows/`, and every step must call
`pnpm --filter <pkg-name> <script>` (or set `working-directory`).

**Why:** GitHub Actions only discovers workflows under the repository-root
`.github/workflows/`; one nested under `lib/<pkg>/.github/workflows/` never
runs. And bare `pnpm <script>` from the repo root fails with "Command not
found" because the package scripts aren't defined at the workspace root. Both
mistakes silently disable the CI/coverage gate. Flagged in review.
