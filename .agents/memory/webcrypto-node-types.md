---
name: WebCrypto algorithm types under @types/node
description: How to reference WebCrypto algorithm-parameter types in a Node lib whose tsconfig has no DOM lib.
---

When typechecking Node code that calls `crypto.subtle` with a tsconfig that uses
`lib: ["es2022"]` and `types: ["node"]` (no DOM), the WebCrypto algorithm
parameter types are NOT global. Names like `AlgorithmIdentifier`, `RsaPssParams`,
`EcdsaParams`, `RsaHashedImportParams`, `EcKeyImportParams`, `HmacImportParams`,
`RsaHashedKeyGenParams`, `EcKeyGenParams`, `HmacKeyGenParams` resolve only inside
the `webcrypto` namespace of `node:crypto`.

**Rule:** reference them as `webcrypto.RsaPssParams` etc. (after
`import { webcrypto } from "node:crypto"`), not as bare globals.

**Why:** `@types/node` declares these inside `namespace webcrypto` in
`crypto.d.ts`; they are not added to the global scope unless lib.dom is included.

**Also:** do NOT try `Parameters<typeof subtle.generateKey>[0]` to dodge the
names — `generateKey`/`importKey`/`sign` are overloaded and `Parameters<>`
collapses to the last overload (`AlgorithmIdentifier`/`Algorithm`), which drops
`modulusLength`, `namedCurve`, `hash`, etc. and breaks object-literal args.

**Also:** `subtle.generateKey(...)` returns `CryptoKey | CryptoKeyPair`; for the
HMAC (symmetric) branch cast to `webcrypto.CryptoKey`.

**BufferSource friction:** under strict lib settings, `Buffer.from(...)` /
`Uint8Array<ArrayBufferLike>` is not assignable to `BufferSource`. Copy into a
fresh `Uint8Array(n)` (which is `Uint8Array<ArrayBuffer>`) before passing to
`subtle.sign/verify/importKey`.
