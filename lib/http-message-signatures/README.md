# @interledger-aligned/http-message-signatures

A standalone, **zero-runtime-dependency**, dual ESM/CJS TypeScript implementation
of [RFC 9421 — HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421),
built for strict spec compliance and **no insecure defaults**.

The implementation is complete and exercised against the RFC 9421 Appendix B
test vectors, with a CI-enforced coverage gate. The public API surface, type
contracts, and fixtures are stable; see the [compliance matrix](#compliance-matrix).

## Why

HTTP Message Signatures (RFC 9421) provide end-to-end integrity and origin
authentication for HTTP requests and responses — independent of the transport.
This library targets correctness and safety for security-sensitive deployments
such as Interledger / Open Payments:

- **Zero runtime dependencies.** No supply-chain surface for a security
  primitive. The Structured Field Values layer (RFC 8941) is implemented
  in-tree, scoped to the subset RFC 9421 exercises.
- **Built on the Web Crypto API.** Runs on Node.js (>= 18) and any runtime that
  exposes `crypto.subtle`.
- **No insecure defaults.** Algorithms must be chosen explicitly; there is no
  fallback algorithm, no silent downgrade, and no ambient default key.
- **Dual ESM/CJS** with per-entry subpath exports (`.`, `./sfv`, `./sign`,
  `./verify`).

## Supported algorithms

| RFC 9421 `alg`        | Primitive                         |
| --------------------- | --------------------------------- |
| `ed25519`             | Ed25519                           |
| `ecdsa-p256-sha256`   | ECDSA over P-256 with SHA-256     |
| `ecdsa-p384-sha384`   | ECDSA over P-384 with SHA-384     |
| `rsa-pss-sha512`      | RSASSA-PSS using SHA-512          |
| `rsa-v1_5-sha256`     | RSASSA-PKCS1-v1_5 using SHA-256   |
| `hmac-sha256`         | HMAC using SHA-256                |

## Out of scope

- The `Content-Digest` field (RFC 9530) is not part of RFC 9421. Digest
  computation is the caller's responsibility — compute it, set the header, and
  cover `content-digest` as a component if body integrity matters.

## Install

```sh
npm install @interledger-aligned/http-message-signatures
```

## Usage

The example below signs a request with an Ed25519 key and verifies it under a
strict policy. It is the same flow as the runnable
[`examples/sign-and-verify.ts`](./examples/sign-and-verify.ts) (modeled on
RFC 9421 Appendix B.2); run it with `node --import tsx examples/sign-and-verify.ts`.

```ts
import { webcrypto } from "node:crypto";
import {
  signMessage,
  verifyMessage,
  type RequestLike,
  type SigningKey,
  type VerifyingKey,
} from "@interledger-aligned/http-message-signatures";

const ALG = "ed25519" as const;
const KEYID = "test-key-ed25519";

// Key material (in production these come from your key store / JWKS).
const pair = (await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, [
  "sign",
  "verify",
])) as webcrypto.CryptoKeyPair;

const signingKey: SigningKey = {
  alg: ALG,
  keyid: KEYID,
  sign: async (data) =>
    new Uint8Array(await webcrypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, data)),
};

const verifyingKey: VerifyingKey = {
  algs: [ALG],
  verify: (data, sig) => webcrypto.subtle.verify({ name: "Ed25519" }, pair.publicKey, sig, data),
};

const request: RequestLike = {
  method: "POST",
  url: "https://example.com/foo?param=Value&Pet=dog",
  headers: { host: "example.com", "content-type": "application/json" },
};

// Sign — the algorithm is explicit; `created` makes the signature freshness-checkable.
const { signatureInput, signature } = await signMessage(request, {
  key: signingKey,
  components: ["@method", "@authority", "@path", "content-type"],
  params: { created: Math.floor(Date.now() / 1000), keyid: KEYID, alg: ALG },
});

// Verify under a strict policy.
const result = await verifyMessage(
  { ...request, headers: { ...request.headers, "signature-input": signatureInput, signature } },
  {
    keyLookup: (keyid, alg) => (keyid === KEYID && alg === ALG ? verifyingKey : null),
    policy: {
      allowedAlgorithms: [ALG],
      requiredCoveredComponents: ["@method", "@authority", "@path"],
      maxAgeSeconds: 300,
    },
  },
);

console.log(result.valid); // true
```

### API notes

- **Signing requires an explicit algorithm** — either carried by a `SigningKey`
  (which bundles its `alg`), or via the `alg` option when passing a raw
  `CryptoKey`. There is no default.
- **Verification is policy-driven.** Callers supply a `keyLookup` plus a
  `VerifierPolicy` describing accepted algorithms, required covered components,
  freshness window (`maxAgeSeconds`, `clockTolerance`), `requireExpires`, an
  optional `tag`, and an optional `nonceVerify` replay hook.
- **`verifyMessage` never throws on a merely-invalid signature** — it returns
  `{ valid: false, reason }`. It throws only on a *malformed* envelope
  (`MalformedSignatureError`) or an unsupported algorithm token
  (`UnsupportedAlgorithmError`).

### Subpath exports

Import the whole surface from the root, or just the layer you need:

```ts
import { signMessage } from "@interledger-aligned/http-message-signatures/sign";
import { verifyMessage } from "@interledger-aligned/http-message-signatures/verify";
import { parseDictionary } from "@interledger-aligned/http-message-signatures/sfv";
```

## Compliance matrix

Each RFC 9421 area maps to a dedicated test suite. All suites pass, and a CI
coverage gate enforces >= 95% line/function and >= 90% branch coverage over
`src/`.

| Area                                   | RFC reference        | Test suite                  | Status   |
| -------------------------------------- | -------------------- | --------------------------- | -------- |
| Structured Field Values (parse + serialize) | RFC 8941        | `sfv.spec`, `sfv-coverage.spec` | passing |
| Derived components                     | RFC 9421 §2.2        | `derived.spec`, `base-coverage.spec` | passing |
| HTTP field components (`sf`/`bs`/`key`/`req`/`tr`) | RFC 9421 §2.1   | `fields.spec`, `base-coverage.spec` | passing |
| Signature base construction            | RFC 9421 §2.5        | `signature-base.spec`       | passing  |
| Appendix B test vectors                | RFC 9421 App. B.2–B.3| `vectors.spec`              | passing  |
| Sign → verify round-trip (all algs)    | RFC 9421 §3.1–3.2    | `roundtrip.spec`, `rawkey.spec` | passing |
| Security / negative cases              | RFC 9421 §7          | `security.spec`, `hardening.spec` | passing |
| Strict `@signature-params` typing      | RFC 9421 §2.3        | `hardening.spec`, `verify-coverage.spec` | passing |
| `@query-param` re-encoding             | RFC 9421 §2.2.8      | `hardening.spec`            | passing  |
| Public API & error taxonomy            | —                    | `api.spec`                  | passing  |

The Appendix B vectors are independently validated against the published RFC
keys by `scripts/validate-fixtures.ts` (run `pnpm validate:fixtures`).

> The coverage gate is measured over executable `src/` only; the type-only
> `src/types.ts` (no emitted JS) and the `test/` tree are excluded.

## Development

```sh
pnpm test                  # run the full suite
pnpm test:coverage         # run with coverage (table; type-only files excluded)
pnpm test:coverage:check   # enforce the CI coverage thresholds over src/
pnpm typecheck             # strict type-check of src, tests, and scripts
pnpm validate:fixtures     # prove the Appendix B fixtures against the RFC keys
pnpm build                 # emit dual ESM + CJS builds with type declarations
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the workflow and
[SECURITY.md](./SECURITY.md) for the security model and reporting process.

## License

[Apache-2.0](./LICENSE). Test vectors and example messages reproduced from
RFC 9421 are Code Components under the Revised BSD License — see [NOTICE](./NOTICE).
