# @interledger-aligned/http-message-signatures

A standalone, **zero-runtime-dependency**, dual ESM/CJS TypeScript implementation
of [RFC 9421 — HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421),
built for strict spec compliance and **no insecure defaults**.

> **Status: in active development (TDD red phase).**
> The public API surface, type contracts, fixtures, and the full test suite are
> in place. Core signing/verification logic is being driven test-first against
> the RFC 9421 Appendix B vectors and is **not yet implemented**. This package is
> not yet published to npm. See the [compliance matrix](#compliance-matrix) for
> the current per-section status.

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

- The `Content-Digest` field (RFC 9530) is not part of RFC 9421. An integration
  example may be provided, but digest computation is the caller's responsibility.

## Install

Not yet published. Once released:

```sh
npm install @interledger-aligned/http-message-signatures
```

## Planned API

> The shapes below reflect the intended public surface (already encoded in the
> type definitions and test suite). They will work once the core logic lands.

```ts
import { signMessage } from "@interledger-aligned/http-message-signatures/sign";
import { verifyMessage } from "@interledger-aligned/http-message-signatures/verify";
```

Signing requires an explicit algorithm (via a `SigningKey` that carries its
`alg`, or via the `alg` option when passing a raw `CryptoKey`). Verification is
policy-driven: callers supply a key-lookup function plus a policy describing the
required covered components, accepted algorithms, and freshness window.

## Compliance matrix

Each RFC 9421 area maps to a dedicated test suite. Status reflects the current
TDD phase — specs are written and **failing by design** until the corresponding
implementation layer is approved and built.

| Area                                   | RFC reference        | Test suite                  | Status        |
| -------------------------------------- | -------------------- | --------------------------- | ------------- |
| Structured Field Values (serialize)    | RFC 8941             | `sfv.spec`                  | spec written  |
| Derived components                     | RFC 9421 §2.2        | `derived.spec`              | spec written  |
| HTTP field components                  | RFC 9421 §2.1        | `fields.spec`               | spec written  |
| Signature base construction            | RFC 9421 §2.5        | `signature-base.spec`       | spec written  |
| Appendix B test vectors                | RFC 9421 App. B.2–B.3| `vectors.spec`              | spec written  |
| Sign → verify round-trip (all algs)    | RFC 9421 §3.1–3.2    | `roundtrip.spec`            | spec written  |
| Security / negative cases              | RFC 9421 §7          | `security.spec`             | spec written  |
| Public API & error taxonomy            | —                    | `api.spec`                  | passing       |

The Appendix B vectors themselves are independently validated against the
published RFC keys by `scripts/validate-fixtures.ts` (run `pnpm validate:fixtures`).

## Development

```sh
pnpm test               # run the full suite (red until core logic lands)
pnpm test:coverage      # run with V8 coverage
pnpm typecheck          # strict type-check of src, tests, and scripts
pnpm validate:fixtures  # prove the Appendix B fixtures against the RFC keys
pnpm build              # emit dual ESM + CJS builds with type declarations
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the test-first workflow and
[SECURITY.md](./SECURITY.md) for the security model and reporting process.

## License

[Apache-2.0](./LICENSE). Test vectors and example messages reproduced from
RFC 9421 are Code Components under the Revised BSD License — see [NOTICE](./NOTICE).
