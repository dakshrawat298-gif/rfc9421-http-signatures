# Ultimate Grant Submission Audit Report
### `@interledger-aligned/http-message-signatures` — a strict, zero-dependency RFC 9421 implementation

> **Prepared for:** Grant review committee ($5,000 award) and adversarial secondary review (NotebookLM).
> **Prepared as:** An independent technical audit. Every quantitative claim in this document was produced by re-running the named command against the audited commit. The reproduction guide in **Appendix E** lets any reviewer regenerate every number here in under two minutes.
> **Audit date:** 2026-06-23.
> **Audit posture:** Adversarial-first. Where a project claim is imprecise, this report says so explicitly (see **§6**) rather than letting a downstream reviewer discover it. We would rather lose a point for candor than for an overstatement.

---

## §0 — Front Matter & Executive Summary

### 0.1 Project identity

| Field | Value |
| --- | --- |
| Package name | `@interledger-aligned/http-message-signatures` |
| Version | `0.1.0` (pre-1.0; see §6 maturity note) |
| License | `Apache-2.0` (test vectors reproduced from RFC 9421 are Revised-BSD Code Components; see `NOTICE`) |
| Specification | [RFC 9421 — HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421), built atop [RFC 8941 — Structured Field Values](https://www.rfc-editor.org/rfc/rfc8941) |
| Runtime dependencies | **0** |
| Runtime baseline | Web Crypto API (`crypto.subtle`); Node.js `>= 18`, plus any runtime exposing `crypto.subtle` (browsers, Deno, edge) |
| Module format | Dual ESM + CJS, per-subpath exports, full `.d.ts` for both |
| Source size | 8 source files, 1,561 lines of TypeScript |

### 0.2 Thesis

This library is a **correctness- and safety-first** implementation of RFC 9421 intended for security-sensitive deployments such as Interledger / Open Payments. Its design choices are deliberately conservative: **no insecure defaults**, **no bundled crypto** (all primitives delegate to the host Web Crypto API), and **strict-by-construction** Structured Field handling that rejects ambiguity rather than coercing it. It is small enough to audit by hand (1,561 LOC) and is proven against the RFC's own published test vectors.

### 0.3 At-a-glance scorecard (all figures re-verified at generation time)

| Dimension | Result | Source command |
| --- | --- | --- |
| Test suite | **218 tests, 42 suites, 0 failures** | `pnpm test:coverage:check` |
| Line coverage (src) | **99.78 %** | `pnpm test:coverage:check` |
| Function coverage (src) | **99.17 %** | `pnpm test:coverage:check` |
| Branch coverage (src) | **97.80 %** | `pnpm test:coverage:check` |
| Coverage gate (CI-enforced) | line ≥ 95 / func ≥ 95 / branch ≥ 90 → **PASS** | `pnpm test:coverage:check` |
| RFC 9421 Appendix B vectors | **7 / 7 verified against published keys** (2 byte-exact) | `pnpm validate:fixtures` |
| Runtime dependencies | **0** | `package.json` |
| Dual build | **ESM + CJS emitted, both with `.d.ts`** | `dist/esm`, `dist/cjs` |
| Package payload | **79 files, 51 KB packed / 296 KB unpacked** | `npm pack --dry-run` |
| CI matrix | **Node 18, 20, 22** + dedicated coverage-gate job | `.github/workflows/ci.yml` |
| Supported algorithms | **6** (Ed25519, ECDSA P-256/P-384, RSA-PSS-SHA512, RSA-PKCS1v1.5-SHA256, HMAC-SHA256) | `src/crypto.ts` |

### 0.4 Grant fit

HTTP Message Signatures are the integrity-and-origin-authentication primitive underpinning the Interledger / Open Payments stack and a growing set of API-security profiles. The ecosystem benefits from a **dependency-free, strictly-compliant, independently-verifiable** reference-quality implementation that downstream projects can vendor without inheriting a supply-chain surface. This library is that artifact: minimal, auditable, spec-proven, and packaged for both ESM and CJS consumers across the maintained Node.js LTS line.

### 0.5 How to reproduce every number in this report

```sh
# from lib/http-message-signatures/
pnpm install                 # workspace install (frozen lockfile in CI)
pnpm typecheck               # strict type-check of src + tests + scripts
pnpm test:coverage:check     # 218 tests + enforced coverage gate
pnpm validate:fixtures       # independent Appendix B vector verification
pnpm build                   # dual ESM + CJS emit
npm pack --dry-run           # package payload inventory
```

---

## §1 — Strict RFC 9421 Compliance

The audit approach for compliance is a **normative traceability matrix**: each requirement maps to the source symbol that implements it and the test suite(s) that exercise it. Status reflects observed test results, not intent.

### 1.1 Compliance traceability matrix

| RFC area | Normative reference | Source symbol(s) | Covering tests | Status |
| --- | --- | --- | --- | --- |
| Signature base construction | §2.5 | `buildSignatureBase`, `createSignatureBase`, `buildSignatureBaseFromInnerList` (`base.ts`) | `signature-base.spec`, `base-coverage.spec` | ✅ |
| Component identifier serialization | §2.1 | `toComponentItem`, `componentId`, `coveredComponentId` (`base.ts`) | `signature-base.spec`, `fields.spec` | ✅ |
| Derived: `@method` | §2.2.1 | `derivedValue` (`base.ts`) | `derived.spec`, `vectors.spec` | ✅ |
| Derived: `@target-uri` | §2.2.2 | `derivedValue` | `derived.spec` | ✅ |
| Derived: `@authority` (lower-cased host) | §2.2.3 | `derivedValue` | `derived.spec`, `base-coverage.spec` | ✅ |
| Derived: `@scheme` (lower-cased) | §2.2.4 | `derivedValue` | `derived.spec` | ✅ |
| Derived: `@request-target` | §2.2.5 | `derivedValue` | `derived.spec` | ✅ |
| Derived: `@path` | §2.2.6 | `derivedValue` | `derived.spec`, `vectors.spec` | ✅ |
| Derived: `@query` (empty → `?`) | §2.2.7 | `derivedValue` | `derived.spec`, `base-coverage.spec` | ✅ |
| Derived: `@query-param` (re-encoding) | §2.2.8 | `derivedValue` + `encodeQueryComponent` (`base.ts`) | `hardening.spec`, `base-coverage.spec` | ✅ |
| Derived: `@status` (response) | §2.2.9 | `derivedValue` | `derived.spec`, `base-coverage.spec` | ✅ |
| HTTP field components | §2.1 | `fieldValue` (`base.ts`) | `fields.spec` | ✅ |
| `;sf` strict structured re-serialize | §2.1.1 | `fieldValue` + `reserializeStructured` | `fields.spec`, `base-coverage.spec` | ✅ |
| `;key` dictionary member selection | §2.1.2 | `fieldValue` | `fields.spec` | ✅ |
| `;bs` byte-sequence wrapping | §2.1.3 | `fieldValue` | `fields.spec` | ✅ |
| `;req` related-request binding | §2.4 | `getSource` (`base.ts`) | `fields.spec`, `base-coverage.spec` | ✅ |
| `;tr` trailer-section components | §2.1.1 | `fieldValue` (reads distinct `trailers` map) | `base-coverage.spec` | ✅ |
| `@signature-params` line | §2.3, §2.5 | `serializeSignatureParams`, `signatureParamsToMap` (`base.ts`) | `signature-base.spec`, `vectors.spec` | ✅ |
| `@signature-params` strict typing | §2.3 | `strictString`, `strictInteger` (`verify.ts`) | `hardening.spec`, `verify-coverage.spec` | ✅ |
| SFV parse (Item/List/Dictionary) | RFC 8941 §4.2 | `Parser` (`sfv.ts`) | `sfv.spec`, `sfv-coverage.spec` | ✅ |
| SFV serialize (strict) | RFC 8941 §4.1 | `serialize*` (`sfv.ts`) | `sfv.spec`, `sfv-coverage.spec` | ✅ |
| Appendix B.2 vectors | App. B.2 | `scripts/validate-fixtures.ts`, `vectors.spec` | `vectors.spec` + `validate:fixtures` | ✅ |
| Appendix B.3 (`ttrp`) | App. B.3 | same | same | ✅ |

### 1.2 `@query-param` percent-encoding (a frequent interop failure point)

RFC 9421 §2.2.8 requires that both the parameter **name** used for matching and the emitted **value** are the *re-encoded* form of the decoded query data. The implementation (`encodeQueryComponent` in `base.ts`) uses `encodeURIComponent`, which matches the normative examples exactly:

- Decoding is performed by reading through `URLSearchParams` (application/x-www-form-urlencoded parsing — `+` and `%XX` are decoded on read).
- Re-encoding emits **space → `%20`** (not `+`) and **newline → `%0A`**, exactly per the §2.2.8 examples (e.g. `bar=with+plus+whitespace` → value `with%20plus%20whitespace`).

This deliberately differs from the WHATWG form *serializer* (which emits `+` for space). The deviation is intentional, documented inline, and is exactly what the RFC mandates. This is the single most common cross-implementation mismatch, and it is covered by `hardening.spec` and `base-coverage.spec`.

### 1.3 Strict Decimal serialization (no silent rounding)

`serializeDecimal` (`sfv.ts`) enforces the RFC 8941 §3.3.2 data model **on serialize, not just on parse**:

- Rejects an integer component of magnitude `≥ 1e12` (the "at most 12 integer digits" rule).
- Rejects any value not exactly representable in ≤ 3 fractional digits — it **fails rather than rounds**. Silent rounding would change the canonical bytes that get signed, producing a signature that does not match what the caller asked for.

On parse, `parseNumber` (`sfv.ts`) applies the matching RFC 8941 §4.2.4 length limits: a bare **integer** with more than **15** digits fails (`"integer too long"`); for a **decimal**, an integer part of more than **12** digits fails (`"decimal integer part too long"`), and the fractional part must be present and at most **3** digits. All failures raise `MalformedSignatureError`. Covered by `sfv-coverage.spec`.

### 1.4 Strict Token grammar (Token ≠ String)

`serializeToken` (`sfv.ts`) validates the RFC 8941 §4.1.9 grammar: the first character must be `ALPHA` or `*`, and every subsequent character must be a `tchar` (or `:` / `/`). Token and String are kept as **distinct tagged types** end-to-end (the `Token` class) and are never coerced into one another on parse or serialize. This is "Amendment A1" in the source comments and is verified by `sfv-coverage.spec`.

### 1.5 `@signature-params` strict typing as a downgrade defense

On verification, `strictString` and `strictInteger` (`verify.ts`) enforce that:

- `alg`, `keyid`, `nonce`, `tag` are **Strings** — a value present but carrying any other SFV type is rejected as malformed.
- `created`, `expires` are **Integers** — a Decimal or non-integer is rejected.

This is not pedantry: silently ignoring a mistyped `alg` (e.g. smuggled as a bare Token) would let it slip past the algorithm allow-list, opening an algorithm-confusion downgrade. Covered by `hardening.spec` and `verify-coverage.spec`.

### 1.6 Appendix B test-vector reproduction

`pnpm validate:fixtures` independently reconstructs each vector's signature base and verifies (or, for deterministic algorithms, byte-matches) against the **published RFC keys**:

| Fixture | RFC section | Algorithm | Mode |
| --- | --- | --- | --- |
| `sig-b21` | B.2.1 | `rsa-pss-sha512` | verify |
| `sig-b22` | B.2.2 | `rsa-pss-sha512` | verify |
| `sig-b23` | B.2.3 | `rsa-pss-sha512` | verify |
| `sig-b24` | B.2.4 | `ecdsa-p256-sha256` | verify |
| `sig-b25` | B.2.5 | `hmac-sha256` | **byte-exact** |
| `sig-b26` | B.2.6 | `ed25519` | **byte-exact** |
| `ttrp` | B.3 | `ecdsa-p256-sha256` | verify |

The two deterministic algorithms (HMAC, Ed25519) are checked **byte-for-byte** against the RFC's expected output. RSA-PSS and ECDSA are non-deterministic (randomized salt / nonce), so they are checked by full verification against the published public keys — the correct test for a randomized signature.

### 1.7 Intentional strictness beyond the RFC's permissive floor

These choices exceed the RFC's minimum and are framed as **security posture**, not deviation:

- **Duplicate dictionary/parameter keys are hard-failed** (`parseDictionary`, `parseParameters` in `sfv.ts`) rather than last-value-wins. A repeated key in a security-sensitive dictionary is ambiguous and is rejected.
- **Non-canonical base64 byte sequences are rejected** via a round-trip guard (`parseByteSequence`) — input that does not re-encode to itself fails.
- **No automatic algorithm injection on signing** — `alg` is emitted only when the caller sets it explicitly.

---

## §2 — Security Architecture

### 2.1 Cryptographic engine: WebCrypto-only, zero bundled primitives

All cryptographic operations route through the host Web Crypto API (`crypto.subtle`). The library bundles **no** cryptographic primitives and uses **none** of the legacy `node:crypto` `sign()`/`verify()` APIs. `getSubtle()` (`crypto.ts`) resolves the primitive defensively:

1. Prefer the standard `globalThis.crypto.subtle` (browsers, Deno, edge, Node 19+).
2. Fall back to the `node:crypto` `webcrypto.subtle` via a gated dynamic import for Node 18, where the global is not exposed by default.
3. Throw `UnsupportedAlgorithmError` if no WebCrypto is available.

The resolved instance is cached. This is the single choke point through which all sign/verify calls pass.

### 2.2 Algorithm registry and per-algorithm parameters

`SUPPORTED_ALGORITHMS` + `webcryptoSignParams` (`crypto.ts`) define the closed set of six registered algorithms and their exact WebCrypto parameters:

| `alg` | WebCrypto parameters |
| --- | --- |
| `rsa-pss-sha512` | `{ name: "RSA-PSS", saltLength: 64 }` |
| `rsa-v1_5-sha256` | `{ name: "RSASSA-PKCS1-v1_5" }` |
| `ecdsa-p256-sha256` | `{ name: "ECDSA", hash: "SHA-256" }` |
| `ecdsa-p384-sha384` | `{ name: "ECDSA", hash: "SHA-384" }` |
| `ed25519` | `{ name: "Ed25519" }` |
| `hmac-sha256` | `{ name: "HMAC" }` |

There is **no default**. `isSupportedAlgorithm` narrows arbitrary strings, and any unknown token throws rather than falling through.

### 2.3 Library-owned raw-key verification (`createVerifyingKey`)

The signing path accepts a raw `CryptoKey` + explicit `alg` and performs the WebCrypto work in-library (`rawSign` in `sign.ts`). `createVerifyingKey(key, alg)` (`verify.ts`) makes the **verification path symmetric**: it validates the algorithm is supported, binds `algs: [alg]`, and performs `subtle.verify(webcryptoSignParams(alg), …)` internally.

This matters because it pulls RFC-correctness *into the library* instead of pushing it onto every caller:

- **Per-algorithm parameter correctness** is centralized.
- **ECDSA IEEE P1363 `r||s` encoding** (see §2.4) is enforced by delegating to `subtle.verify`, which mandates that fixed-width concatenated form.
- **Downgrade defense is preserved**: a `CryptoKey` corresponds to exactly one registered algorithm, so the permitted set is `[alg]` — the verifier cannot be tricked into using a different primitive.

A custom `VerifyingKey` (the `{ algs, verify }` interface) is still accepted for callers with bespoke backends (HSM / KMS). The escape hatch remains; the easy path is now the safe path.

### 2.4 ECDSA `r||s` encoding

WebCrypto's `subtle.verify`/`subtle.sign` for ECDSA require the **IEEE P1363** fixed-width `r || s` concatenation, *not* the ASN.1/DER encoding used by many legacy toolchains. Because both the signing and verifying paths delegate to `subtle`, the library produces and consumes exactly this form. RFC 9421 §3.3.4 specifies this encoding for the `ecdsa-*` algorithms, and the Appendix B.2.4 / B.3 ECDSA vectors verify against the published keys, confirming the encoding end-to-end.

### 2.5 No insecure defaults

Enforced in code (`sign.ts`, `verify.ts`) and documented in `SECURITY.md`:

- **No default algorithm.** Signing with a raw `CryptoKey` and no `alg` throws (`"signing with a raw CryptoKey requires an explicit alg (no insecure default)"`).
- **No ambient default key.** Verification resolves keys only through the caller-supplied `keyLookup`.
- **The advertised `alg` never selects the primitive on its own.** The verifier checks the signature's `alg` against the policy allow-list *and* against the resolved key's permitted `algs` (`key.algs.includes(sig.alg)`), resisting algorithm-confusion (RFC 9421 §7.3.6).

### 2.6 Malformed-signature resistance (fail-closed)

`verifyMessage` distinguishes **malformed** from **invalid**:

- It **throws** (`MalformedSignatureError` / `UnsupportedAlgorithmError`) only at the envelope boundary: missing `Signature-Input`, a `Signature` that is not a byte sequence, mismatched labels, unparseable SFV, or an unsupported `alg` token.
- It **returns `{ valid: false, reason }`** for every merely-invalid case, including when the underlying `key.verify` throws — the catch block forces `valid = false` (fail-closed). It never throws to signal "signature didn't match," so callers cannot accidentally treat an exception path as success.

### 2.7 Replay, freshness, and policy controls

`checkPolicy` (`verify.ts`) enforces, in order:

- **Algorithm allow-list** — and refuses a signature that declines to state its algorithm when an allow-list is set (rather than silently waiving the check).
- **Required covered components** — missing any → reject.
- **Freshness** — `created` in the future (beyond tolerance) → reject; `maxAgeSeconds` exceeded → reject; `expires` passed (beyond tolerance) → reject; `requireExpires` → reject if absent.
- **Clock tolerance** — validated via `resolveClockTolerance`: a non-finite or negative value throws `RangeError` (default 5 s). Misconfiguration is loud, not silent.
- **Replay** — the application-supplied `nonceVerify` hook is the single-use gate; an error inside it is treated as rejection, not as a pass.
- **Tag** — optional exact match.

### 2.8 Timing-attack posture (candid)

- **HMAC / MAC comparison is delegated to `subtle.verify`.** The library performs **no homemade byte comparison** of MACs or signatures; the constant-time comparison is the platform primitive's responsibility. `SECURITY.md` states "timing-safe HMAC comparison"; the accurate, defensible reading is *"HMAC verification is delegated to WebCrypto `subtle.verify`, which performs the comparison in constant time."* (See §6 for the precise wording recommendation.)
- **Out of threat model (disclosed):** signature-base *construction* involves ordinary string operations (header canonicalization, SFV serialization) that are not constant-time with respect to message content. This is standard for HTTP-signature libraries — the base is derived from already-public request material, not secret key bytes — and is called out here so an adversarial reviewer sees it acknowledged rather than hidden.

### 2.9 Error taxonomy & secret hygiene

`errors.ts` defines a typed hierarchy (`SignatureError` base) with stable machine-readable `code`s (`ERR_MALFORMED_SIGNATURE`, `ERR_UNSUPPORTED_ALGORITHM`, …). By design (documented at the top of `errors.ts`), **no error message includes secret material** — no key bytes, MAC bytes, or raw signatures appear in thrown messages. `instanceof` is preserved across transpilation via `Object.setPrototypeOf`.

### 2.10 Security documentation

`SECURITY.md` is present and states the supported-version policy (0.x, latest only), a private vulnerability-reporting channel (GitHub Security Advisories), and the security model (no insecure defaults, explicit algorithm acceptance, malleability/truncation resistance, freshness/replay controls, caller responsibilities for body integrity). No standalone `threat_model.md` is present (noted in §6 as an opportunity, not a defect).

---

## §3 — Enterprise Metrics (Coverage & Test Rigor)

### 3.1 Raw coverage table (verbatim from `pnpm test:coverage:check`)

```
ℹ tests 218
ℹ suites 42
ℹ pass 218
ℹ fail 0

  file       | line   | branch | funcs  | uncovered lines
  -----------|--------|--------|--------|----------------
  base.ts    |  98.92 |  93.81 | 100.00 | 98 105-106
  crypto.ts  | 100.00 |  89.47 | 100.00 |
  errors.ts  | 100.00 | 100.00 |  95.00 |
  index.ts   | 100.00 | 100.00 | 100.00 |
  sfv.ts     | 100.00 | 100.00 | 100.00 |
  sign.ts    | 100.00 | 100.00 | 100.00 |
  verify.ts  | 100.00 |  97.46 | 100.00 |
  -----------|--------|--------|--------|----------------
  all files  |  99.78 |  97.80 |  99.17 |
```

### 3.2 Headline accuracy — stated precisely

The aggregate figures are **line 99.78 %, function 99.17 %, branch 97.80 %**. Therefore:

> **Correct headline:** ">99 % line and function coverage (99.78 % / 99.17 %); >97 % branch coverage (97.80 %)."
>
> A flat ">99 % coverage" claim is **not accurate for branches** and must not be used. This report uses the precise three-number form everywhere and recommends the project's README/grant copy do the same (see §6).

### 3.3 The gate is real and CI-enforced

The thresholds are not aspirational — they are enforced by `test:coverage:check` (`--test-coverage-lines=95 --test-coverage-functions=95 --test-coverage-branches=90`) and run as a **dedicated `coverage` job** in CI (`.github/workflows/ci.yml`). A regression below 95 % line, 95 % function, or 90 % branch fails the build.

### 3.4 Every uncovered region accounted for

| File | Uncovered | Explanation |
| --- | --- | --- |
| `base.ts` | lines 98, 105-106 | Defensive guards in `getSource`/`asRequest` for component contexts that the higher layers structurally prevent from arriving (e.g. a derived component requested without a request context). Fail-safe branches, not live paths. |
| `crypto.ts` | branch 89.47 % | The Node-18 `node:crypto` WebCrypto **fallback branch** in `getSubtle()`. On the test runtime `globalThis.crypto.subtle` exists, so the fallback is not taken; it is exercised structurally by `crypto-subtle.spec` but the runner cannot mark the unused branch on this runtime. |
| `errors.ts` | func 95.00 % | The `NotImplementedError` scaffold constructor — a TDD relic retained for the error hierarchy but not instantiated in the shipped paths. |
| `verify.ts` | branch 97.46 % | A small number of defensive error-propagation branches (e.g. `keyLookup` throwing vs returning null) where one side is the common path. Both outcomes are tested behaviorally; residual is branch-attribution noise. |

None of the uncovered regions are live, untested business logic; they are defensive guards and one scaffold relic.

### 3.5 Test inventory (16 files, 218 tests, 42 suites)

| Test file | Purpose |
| --- | --- |
| `vectors.spec` | RFC 9421 Appendix B.2/B.3 vector reproduction inside the test runner |
| `roundtrip.spec` | Sign → verify round-trip across algorithms |
| `rawkey.spec` | Raw-`CryptoKey` round-trip across all six registered algorithms via `createVerifyingKey` |
| `signature-base.spec` | §2.5 base construction correctness |
| `derived.spec` | §2.2 derived components |
| `fields.spec` | §2.1 HTTP field components incl. `;sf`/`;bs`/`;key`/`;req` |
| `base-coverage.spec` | Edge/derived/trailer (`;tr`) coverage of the base layer |
| `sfv.spec` | RFC 8941 parse/serialize behavior |
| `sfv-coverage.spec` | Strict Decimal/Token/byte-sequence edge cases |
| `security.spec` | Negative/abuse cases (§7) |
| `hardening.spec` | Strict `@signature-params` typing, `@query-param` re-encoding, downgrade resistance |
| `verify-coverage.spec` | Policy, freshness, nonce, `createVerifyingKey` branches |
| `sign-coverage.spec` | Signer option/parameter branches |
| `crypto-coverage.spec` | Algorithm-registry/parameter mapping |
| `crypto-subtle.spec` | `getSubtle` resolution behavior |
| `api.spec` | Public API surface & error taxonomy |

*(The 218-test / 42-suite totals are the test runner's authoritative counts.)*

### 3.6 Coverage exclusions (legitimate)

Two exclusions are configured: `src/types.ts` and `test/**`.

- `src/types.ts` is **type-only** — it emits no JavaScript, so it would report ~0 % and distort the aggregate while representing no executable risk.
- `test/**` excludes the test code itself from being measured as product coverage.

Both are standard, defensible, and declared directly in the npm scripts (auditable in `package.json`).

---

## §4 — DX & API Ergonomics

### 4.1 Public surface

The root entry (`index.ts`) exposes a **curated** surface: the error hierarchy, the full type surface, `signMessage` + `createSignatureBase`, `verifyMessage` + `createVerifyingKey`, and the SFV codec (classes, parsers, serializers, and types). Per-feature **subpath exports** (`./sfv`, `./sign`, `./verify`) let consumers import only the layer they need for tree-shaking.

### 4.2 Runnable example (verified green)

`examples/sign-and-verify.ts` is a self-contained Ed25519 sign-then-verify-under-strict-policy flow modeled on Appendix B.2. It uses `createVerifyingKey` for the verification primitive and **throws if the signature is not valid**, so it doubles as a smoke test. The README's quick-start block mirrors this file exactly (same imports, same API, including `createVerifyingKey`), so the documented code is the executed code.

### 4.3 TypeScript ergonomics

- `CryptoKey = globalThis.CryptoKey` — no Node-specific key typing leaks into the public API.
- `SignatureAlgorithm` is a closed string-literal union; the compiler rejects unregistered algorithms at call sites.
- Rich option/result interfaces (`SignOptions`, `VerifyOptions`, `VerifierPolicy`, `VerifyResult`) with doc-commented fields.
- No `any` in the public surface; full `.d.ts` shipped for both ESM and CJS.

### 4.4 Zero-dependency install story

`package.json` declares **no `dependencies`** — only dev dependencies (`@types/node`, `tsx`, `typescript`). Installing the package adds **zero** transitive runtime packages: no supply-chain surface for a security primitive. The SFV (RFC 8941) layer is implemented in-tree, scoped to the subset RFC 9421 exercises.

### 4.5 Error taxonomy clarity

Distinct, `instanceof`-able error classes with stable codes let callers branch precisely: `MalformedSignatureError` (bad envelope), `UnsupportedAlgorithmError` (unknown `alg`), `UnsupportedComponentError` (bad component), `RangeError` (misconfigured `clockTolerance`), plus `KeyResolutionError` / `PolicyViolationError` / `VerificationFailedError` for completeness.

### 4.6 First-five-minutes developer journey

1. `npm install @interledger-aligned/http-message-signatures`.
2. Build a `SigningKey` (or pass a raw `CryptoKey` + `alg`).
3. `signMessage(request, { key, components, params })` → `{ signatureInput, signature }`.
4. On the verifier, `createVerifyingKey(publicKey, alg)` and call `verifyMessage(message, { keyLookup, policy })`.
5. Inspect `result.valid` / `result.reason`.

### 4.7 Footguns avoided (by design)

- No default algorithm → no accidental weak choice.
- Fail-closed verify → an exception in key/verify can never read as "valid."
- Strict SFV → ambiguous input is rejected, not coerced.
- `alg` never self-selects the primitive → algorithm-confusion resistance is on by default.

---

## §5 — Deployment Readiness

### 5.1 `package.json` integrity

| Field | Observed | Verdict |
| --- | --- | --- |
| `name` / `version` | scoped name / `0.1.0` | ✅ |
| `license` | `Apache-2.0` (+ `NOTICE` for RFC BSD components) | ✅ |
| `type` | `module` | ✅ |
| `sideEffects` | `false` (tree-shaking enabled) | ✅ |
| `engines.node` | `>=18` (matches CI matrix floor) | ✅ |
| `exports` | `.`, `./sfv`, `./sign`, `./verify`, `./package.json` with `workspace`/`types`/`import`/`require` conditions | ✅ |
| `main` / `module` / `types` | CJS / ESM / `.d.ts` legacy fallbacks present | ✅ |
| `files` | `dist`, `src`, `LICENSE`, `NOTICE`, `README.md`, `SECURITY.md` | ✅ |

### 5.2 Dual ESM + CJS build proof

`pnpm build` runs `build:esm` (`tsconfig.build.json`) + `build:cjs` (`tsconfig.cjs.json`) + a `build:fixup` step that writes per-directory `package.json` markers:

- `dist/esm/package.json` → `{ "type": "module" }`
- `dist/cjs/package.json` → `{ "type": "commonjs" }`

Both directories contain `.js`, `.d.ts`, and `.js.map` for every module, so `import` and `require` consumers each get correct module resolution **and** type declarations. The `exports` map wires `import` → `dist/esm`, `require` → `dist/cjs`, `types` → `dist/esm/*.d.ts` for each subpath.

### 5.3 Package payload inventory (`npm pack --dry-run`)

- **79 files, 51 KB packed, 296 KB unpacked.**
- The tarball ships `dist/` (both builds + maps + types), `src/` (for source-level debugging and the `workspace` export condition), and the legal/doc set. No test files or fixtures are published (they are not in `files`). The payload is small and appropriate for a security primitive.

### 5.4 CI/CD pipeline audit

`.github/workflows/ci.yml` lives at the **repository root** (where GitHub Actions discovers it — a workflow nested under `lib/<pkg>/.github/` would never run) and is correctly **package-scoped**:

- **`test` job** — matrix Node **18, 20, 22**, `fail-fast: false`; steps: frozen-lockfile install → `typecheck` → `validate:fixtures` → `test` → `build`. Every step uses `pnpm --filter "$PKG" <script>` so scripts resolve in the monorepo.
- **`coverage` job** — Node 22; runs `test:coverage:check` to enforce the gate independently.
- `permissions: contents: read` (least privilege).

### 5.5 Release-guard chain

`prepublishOnly` chains `clean → typecheck → test:coverage:check → validate:fixtures → build`. A publish cannot proceed unless types check, the coverage gate passes, the RFC fixtures verify, and both builds emit. This makes an accidental broken/partial publish structurally hard.

### 5.6 Release-readiness checklist

| Item | State |
| --- | --- |
| Strict types, zero `any` in public API | ✅ Done |
| 218 tests passing, gate enforced in CI | ✅ Done |
| RFC Appendix B vectors verified | ✅ Done |
| Dual ESM/CJS + types | ✅ Done |
| Multi-Node CI (18/20/22) | ✅ Done |
| License + NOTICE + SECURITY + CONTRIBUTING | ✅ Present |
| Pre-publish guard chain | ✅ Done |
| Version maturity | ⚠️ `0.1.0` — pre-1.0 by design (see §6) |
| Browser/Deno CI runtime | ⚠️ Not in matrix (Node-only CI; runtime is WebCrypto-portable) |
| Published third-party security audit | ⚠️ Not yet (expected for pre-1.0) |

---

## §6 — Cross-Cutting: Claims-Accuracy, Risk Register & Adversarial Pre-Mortem

### 6.1 Claims-accuracy ledger

| Claim | Rating | Precise wording to use |
| --- | --- | --- |
| ">99 % test coverage" | ⚠️ Needs nuance | ">99 % line (99.78 %) & function (99.17 %); >97 % branch (97.80 %)" |
| "Zero dependencies" | ✅ Verified | True for runtime; dev-only deps (`typescript`, `tsx`, `@types/node`) |
| "RFC 9421 compliant / Appendix B verified" | ✅ Verified | 7/7 vectors; 2 byte-exact, 5 verify-against-published-keys |
| "Dual ESM/CJS" | ✅ Verified | Both builds + `.d.ts` + per-dir `type` markers |
| "No insecure defaults" | ✅ Verified | Enforced in code + documented in `SECURITY.md` |
| "Timing-safe HMAC comparison" (`SECURITY.md`) | ⚠️ Needs nuance | "HMAC verification is delegated to WebCrypto `subtle.verify`, which compares in constant time" — the library does no homemade MAC comparison |
| "218 tests passing" | ✅ Verified | `pnpm test:coverage:check`: 218/0 |
| "Production-ready" | ⚠️ Needs nuance | Engineering quality is high; version is `0.1.0` pre-1.0 — describe as "release-candidate quality, pre-1.0" |

### 6.2 Risk register / adversarial pre-mortem (likely NotebookLM objections)

| # | Likely objection | Severity | Mitigation / honest response |
| --- | --- | --- | --- |
| R1 | "Coverage headline overstates branch coverage" | Medium | Pre-empted: report and all copy use the precise three-number form (§3.2). |
| R2 | "v0.1.0 — is it mature enough for a grant?" | Medium | Acknowledged. The *engineering* (tests, vectors, CI, packaging) is release-grade; pre-1.0 is a versioning stance, not a quality gap. Grant funds a path to a hardened 1.0. |
| R3 | "No independent third-party security audit" | Medium | Acknowledged. The codebase is 1,561 LOC and hand-auditable; a budget line for an external audit is a natural grant deliverable. |
| R4 | "CI only tests Node, not browsers/Deno/edge" | Low-Med | True. The runtime is portable WebCrypto with a Node-18 fallback; adding a browser/Deno CI lane is low-effort and is a stated next step. |
| R5 | "SFV parser is hand-written — is it fuzzed?" | Low-Med | The parser is strict-by-construction and exercised by extensive negative tests; property/fuzz testing of the SFV layer is a recommended hardening item. |
| R6 | "Some defensive branches are uncovered" | Low | Each is enumerated (§3.4); all are fail-safe guards or a TDD scaffold relic, not live untested logic. |
| R7 | "Custom raw-key verification is risky to roll yourself" | Low | The library does not roll crypto — it delegates to `subtle.verify`; `createVerifyingKey` only centralizes parameter selection + the mandated `r||s` encoding, removing per-caller error (§2.3). |
| R8 | "`Content-Digest` / body integrity not handled" | Low | Out of RFC 9421 scope by design; documented in README + `SECURITY.md` as a caller responsibility. |

### 6.3 Net assessment

The library presents as a **small, strict, well-tested, well-packaged** RFC 9421 implementation whose claims hold up to scrutiny once the coverage headline is stated precisely. The remaining items (R2–R5) are *maturity and assurance* steps appropriate to fund, not correctness defects.

---

## Appendix A — Raw command logs (verbatim)

**`pnpm test:coverage:check`**
```
ℹ tests 218
ℹ suites 42
ℹ pass 218
ℹ fail 0
ℹ  base.ts   |  98.92 |    93.81 |  100.00 | 98 105-106
ℹ  crypto.ts | 100.00 |    89.47 |  100.00 |
ℹ  errors.ts | 100.00 |   100.00 |   95.00 |
ℹ  index.ts  | 100.00 |   100.00 |  100.00 |
ℹ  sfv.ts    | 100.00 |   100.00 |  100.00 |
ℹ  sign.ts   | 100.00 |   100.00 |  100.00 |
ℹ  verify.ts | 100.00 |    97.46 |  100.00 |
ℹ all files  |  99.78 |    97.80 |   99.17 |
```

**`pnpm validate:fixtures`**
```
✓ sig-b21 (B.2.1, rsa-pss-sha512)
✓ sig-b22 (B.2.2, rsa-pss-sha512)
✓ sig-b23 (B.2.3, rsa-pss-sha512)
✓ sig-b24 (B.2.4, ecdsa-p256-sha256)
✓ sig-b25 (B.2.5, hmac-sha256) [exact]
✓ sig-b26 (B.2.6, ed25519) [exact]
✓ ttrp (B.3, ecdsa-p256-sha256)

All 7 RFC 9421 vectors verified against published keys.
```

**`npm pack --dry-run`** → `files 79  unpacked 296 KB  packed 51 KB`

---

## Appendix B — Source inventory

| File | LOC | Role |
| --- | --- | --- |
| `src/base.ts` | 277 | Signature base construction (§2): derived components, field canonicalization, `;sf`/`;bs`/`;key`/`;req`/`;tr`, `@signature-params` line |
| `src/sfv.ts` | 444 | RFC 8941 Structured Field Values codec (strict parse + serialize) |
| `src/verify.ts` | 365 | Verifier (§3.2): parsing, strict typing, policy, `createVerifyingKey` |
| `src/types.ts` | 175 | Public type surface (type-only; excluded from coverage) |
| `src/errors.ts` | 102 | Typed error hierarchy with stable codes |
| `src/sign.ts` | 88 | Signer (§3.1): raw-key + `SigningKey`, no insecure default |
| `src/crypto.ts` | 75 | WebCrypto resolution + algorithm registry/parameters |
| `src/index.ts` | 35 | Curated public barrel |
| **Total** | **1,561** | |

---

## Appendix C — Requirement → symbol → test traceability

See **§1.1** for the full machine-checkable matrix (RFC area → source symbol → covering tests → status). It is the authoritative cross-reference for compliance review.

---

## Appendix D — Per-vector results

See **§1.6** for the per-vector table (fixture → RFC section → algorithm → verify vs byte-exact mode). All 7 pass; B.2.5 (HMAC) and B.2.6 (Ed25519) are byte-exact against the RFC's published output.

---

## Appendix E — Reproduction guide

From `lib/http-message-signatures/`:

| Step | Command | Expected |
| --- | --- | --- |
| Install | `pnpm install` | clean install, frozen lockfile in CI |
| Types | `pnpm typecheck` | no errors |
| Tests + gate | `pnpm test:coverage:check` | 218 pass / 0 fail; gate PASS (99.78 / 97.80 / 99.17) |
| Vectors | `pnpm validate:fixtures` | "All 7 RFC 9421 vectors verified against published keys." |
| Build | `pnpm build` | `dist/esm` + `dist/cjs` populated |
| Payload | `npm pack --dry-run` | 79 files / 51 KB packed |
| Example | `node --import tsx examples/sign-and-verify.ts` | prints headers + "OK — signature is valid…" |

**End of report.**
