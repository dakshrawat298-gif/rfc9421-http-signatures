/**
 * Internal: maps registered RFC 9421 algorithm identifiers (§6.2.2) to the
 * WebCrypto parameters used when signing/verifying with a raw `CryptoKey`.
 */

import { UnsupportedAlgorithmError } from "./errors.js";
import type { SignatureAlgorithm } from "./types.js";

let cachedSubtle: SubtleCrypto | undefined;

/**
 * Resolve the runtime WebCrypto {@link SubtleCrypto}, preferring the standard
 * `globalThis.crypto.subtle` (browsers, Deno, edge runtimes, Node 19+). On
 * Node 18 — where the global is not exposed by default — fall back to the
 * `node:crypto` WebCrypto instance via a gated dynamic import. The legacy
 * `node:crypto` `sign()`/`verify()` APIs are never used.
 */
export async function getSubtle(): Promise<SubtleCrypto> {
  if (cachedSubtle) return cachedSubtle;
  const globalSubtle = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;
  if (globalSubtle) {
    cachedSubtle = globalSubtle;
    return cachedSubtle;
  }
  const nodeSubtle = (await import("node:crypto")).webcrypto?.subtle as SubtleCrypto | undefined;
  if (nodeSubtle) {
    cachedSubtle = nodeSubtle;
    return cachedSubtle;
  }
  throw new UnsupportedAlgorithmError(
    "WebCrypto is unavailable: this runtime exposes no globalThis.crypto.subtle",
  );
}

/** The registered, supported algorithm identifiers. */
export const SUPPORTED_ALGORITHMS: readonly SignatureAlgorithm[] = [
  "rsa-pss-sha512",
  "rsa-v1_5-sha256",
  "ecdsa-p256-sha256",
  "ecdsa-p384-sha384",
  "ed25519",
  "hmac-sha256",
];

/** Narrow an arbitrary string to a supported {@link SignatureAlgorithm}. */
export function isSupportedAlgorithm(alg: string): alg is SignatureAlgorithm {
  return (SUPPORTED_ALGORITHMS as readonly string[]).includes(alg);
}

type SignAlg =
  | { name: "RSASSA-PKCS1-v1_5" }
  | { name: "RSA-PSS"; saltLength: number }
  | { name: "ECDSA"; hash: "SHA-256" | "SHA-384" }
  | { name: "Ed25519" }
  | { name: "HMAC" };

/** WebCrypto sign/verify parameters for a registered algorithm. */
export function webcryptoSignParams(alg: SignatureAlgorithm): SignAlg {
  switch (alg) {
    case "rsa-pss-sha512":
      return { name: "RSA-PSS", saltLength: 64 };
    case "rsa-v1_5-sha256":
      return { name: "RSASSA-PKCS1-v1_5" };
    case "ecdsa-p256-sha256":
      return { name: "ECDSA", hash: "SHA-256" };
    case "ecdsa-p384-sha384":
      return { name: "ECDSA", hash: "SHA-384" };
    case "ed25519":
      return { name: "Ed25519" };
    case "hmac-sha256":
      return { name: "HMAC" };
    default:
      throw new UnsupportedAlgorithmError(`unsupported algorithm: ${String(alg)}`);
  }
}
