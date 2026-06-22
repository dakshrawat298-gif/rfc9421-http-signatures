/**
 * Internal: maps registered RFC 9421 algorithm identifiers (§6.2.2) to the
 * WebCrypto parameters used when signing/verifying with a raw `CryptoKey`.
 */

import type { webcrypto } from "node:crypto";

import { UnsupportedAlgorithmError } from "./errors.js";
import type { SignatureAlgorithm } from "./types.js";

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

type SignAlg = webcrypto.AlgorithmIdentifier | webcrypto.RsaPssParams | webcrypto.EcdsaParams;

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
