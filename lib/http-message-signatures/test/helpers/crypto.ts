/**
 * Test-only key helpers built on the platform WebCrypto (NOT the library under
 * test). They wrap CryptoKeys in the library's {@link SigningKey} /
 * {@link VerifyingKey} abstractions so the suites can drive sign/verify without
 * the library yet owning key import.
 */

import { webcrypto } from "node:crypto";
import type { SignatureAlgorithm, SigningKey, VerifyingKey } from "../../src/types.js";
import { KEYS } from "../fixtures/rfc9421-vectors.js";

const { subtle } = webcrypto;

/** Copy into a fresh ArrayBuffer-backed view (satisfies WebCrypto BufferSource). */
function ab(src: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(src.byteLength);
  out.set(src);
  return out;
}

export function pemToDer(pem: string): Uint8Array<ArrayBuffer> {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  return ab(new Uint8Array(Buffer.from(body, "base64")));
}

export function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  return ab(new Uint8Array(Buffer.from(b64, "base64")));
}

export function bytesToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

type SignAlg = webcrypto.AlgorithmIdentifier | webcrypto.RsaPssParams | webcrypto.EcdsaParams;
type ImportAlg =
  | webcrypto.AlgorithmIdentifier
  | webcrypto.RsaHashedImportParams
  | webcrypto.EcKeyImportParams
  | webcrypto.HmacImportParams;
type GenAlg =
  | webcrypto.AlgorithmIdentifier
  | webcrypto.RsaHashedKeyGenParams
  | webcrypto.EcKeyGenParams
  | webcrypto.HmacKeyGenParams;

function signParams(alg: SignatureAlgorithm): SignAlg {
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
      throw new Error(`unknown alg ${String(alg)}`);
  }
}

function importParams(alg: SignatureAlgorithm): ImportAlg {
  switch (alg) {
    case "rsa-pss-sha512":
      return { name: "RSA-PSS", hash: "SHA-512" };
    case "rsa-v1_5-sha256":
      return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    case "ecdsa-p256-sha256":
      return { name: "ECDSA", namedCurve: "P-256" };
    case "ecdsa-p384-sha384":
      return { name: "ECDSA", namedCurve: "P-384" };
    case "ed25519":
      return { name: "Ed25519" };
    case "hmac-sha256":
      return { name: "HMAC", hash: "SHA-256" };
    default:
      throw new Error(`unknown alg ${String(alg)}`);
  }
}

function wrapSigning(
  cryptoKey: webcrypto.CryptoKey,
  alg: SignatureAlgorithm,
  keyid?: string,
): SigningKey {
  return {
    alg,
    ...(keyid !== undefined ? { keyid } : {}),
    async sign(data: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(await subtle.sign(signParams(alg), cryptoKey, ab(data)));
    },
  };
}

function wrapVerifying(cryptoKey: webcrypto.CryptoKey, alg: SignatureAlgorithm): VerifyingKey {
  return {
    algs: [alg],
    async verify(data: Uint8Array, signature: Uint8Array): Promise<boolean> {
      return subtle.verify(signParams(alg), cryptoKey, ab(signature), ab(data));
    },
  };
}

/** Verifying key for an Appendix B fixture (all public keys are SPKI or raw). */
export async function fixtureVerifyingKey(
  alg: SignatureAlgorithm,
  keyid: string,
): Promise<VerifyingKey> {
  if (alg === "hmac-sha256") {
    const raw = b64ToBytes(KEYS["test-shared-secret"].secretBase64);
    const k = await subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, [
      "verify",
    ]);
    return wrapVerifying(k, alg);
  }
  const entry = KEYS[keyid as Exclude<keyof typeof KEYS, "test-shared-secret">];
  const der = pemToDer(entry.public);
  const k = await subtle.importKey("spki", der, importParams(alg), false, ["verify"]);
  return wrapVerifying(k, alg);
}

/** Signing key for the deterministic Appendix B fixtures (Ed25519, HMAC). */
export async function fixtureSigningKey(
  alg: "ed25519" | "hmac-sha256",
  keyid: string,
): Promise<SigningKey> {
  if (alg === "hmac-sha256") {
    const raw = b64ToBytes(KEYS["test-shared-secret"].secretBase64);
    const k = await subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
    ]);
    return wrapSigning(k, alg, keyid);
  }
  const der = pemToDer(KEYS["test-key-ed25519"].private);
  const k = await subtle.importKey("pkcs8", der, { name: "Ed25519" }, false, ["sign"]);
  return wrapSigning(k, alg, keyid);
}

function genParamsFor(alg: SignatureAlgorithm): GenAlg {
  switch (alg) {
    case "rsa-pss-sha512":
      return {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-512",
      };
    case "rsa-v1_5-sha256":
      return {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      };
    case "ecdsa-p256-sha256":
      return { name: "ECDSA", namedCurve: "P-256" };
    case "ecdsa-p384-sha384":
      return { name: "ECDSA", namedCurve: "P-384" };
    case "ed25519":
      return { name: "Ed25519" };
    case "hmac-sha256":
      return { name: "HMAC", hash: "SHA-256" };
    default:
      throw new Error(`unknown alg ${String(alg)}`);
  }
}

/** Generate an ephemeral signer/verifier pair for round-trip tests. */
export async function generateSigner(
  alg: SignatureAlgorithm,
  keyid?: string,
): Promise<{ signing: SigningKey; verifying: VerifyingKey }> {
  if (alg === "hmac-sha256") {
    const k = (await subtle.generateKey(genParamsFor(alg), true, [
      "sign",
      "verify",
    ])) as webcrypto.CryptoKey;
    return { signing: wrapSigning(k, alg, keyid), verifying: wrapVerifying(k, alg) };
  }

  const pair = (await subtle.generateKey(genParamsFor(alg), true, [
    "sign",
    "verify",
  ])) as webcrypto.CryptoKeyPair;
  return {
    signing: wrapSigning(pair.privateKey, alg, keyid),
    verifying: wrapVerifying(pair.publicKey, alg),
  };
}

/**
 * Generate a raw private `CryptoKey` (no embedded algorithm metadata) for
 * tests that assert the library rejects signing without an explicit algorithm.
 */
export async function generateRawSigningKey(
  alg: SignatureAlgorithm,
): Promise<webcrypto.CryptoKey> {
  if (alg === "hmac-sha256") {
    return (await subtle.generateKey(genParamsFor(alg), true, [
      "sign",
      "verify",
    ])) as webcrypto.CryptoKey;
  }
  const pair = (await subtle.generateKey(genParamsFor(alg), true, [
    "sign",
    "verify",
  ])) as webcrypto.CryptoKeyPair;
  return pair.privateKey;
}
