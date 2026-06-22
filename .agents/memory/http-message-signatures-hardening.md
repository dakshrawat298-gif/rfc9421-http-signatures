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
