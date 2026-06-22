# Security Policy

## Supported versions

This library is pre-1.0 and under active development. Until a stable release is
cut, only the latest commit on the default branch receives security fixes.

| Version   | Supported          |
| --------- | ------------------ |
| `0.x`     | :white_check_mark: (latest only) |

## Reporting a vulnerability

**Please do not open public issues for security vulnerabilities.**

Report suspected vulnerabilities privately via GitHub Security Advisories
("Report a vulnerability" on the repository's *Security* tab). Include:

- a description of the issue and its impact,
- a minimal reproduction (message, key material — use throwaway keys — and the
  observed vs. expected behavior), and
- the affected version or commit.

We aim to acknowledge reports within a few business days and to coordinate
disclosure once a fix is available.

## Security model

This library implements RFC 9421 with a deliberately conservative posture:

- **No insecure defaults.** There is no default algorithm and no ambient default
  key. The signing algorithm must be specified explicitly — either carried by a
  `SigningKey` or passed alongside a raw `CryptoKey`. Signing without a
  determinable algorithm is rejected.
- **Explicit algorithm acceptance on verification.** Verifiers declare which
  algorithms they accept. The `alg` advertised in a signature's parameters is
  never trusted to select the verification primitive on its own; this resists
  algorithm-confusion / downgrade attacks (RFC 9421 §7.3.6).
- **Timing-safe HMAC comparison.** Symmetric (HMAC) verification uses a
  constant-time comparison to avoid timing side channels.
- **Malleability and truncation resistance.** Signatures with unexpected
  encodings, truncated bytes, or non-canonical ECDSA components are rejected
  rather than coerced.
- **Freshness and replay controls.** Verification policy supports a maximum age
  and clock tolerance for the `created` parameter, plus required-component and
  nonce checks, so stale or replayed signatures can be refused.
- **Caller responsibilities.** Message body integrity (e.g. `Content-Digest`,
  RFC 9530) is out of scope; include and cover such a field if body integrity
  matters. Protect private key material and nonce stores appropriately.

## Cryptographic dependencies

All cryptographic operations are performed by the host's Web Crypto API
(`crypto.subtle`). This library contains no bundled cryptographic primitives and
no third-party runtime dependencies.
