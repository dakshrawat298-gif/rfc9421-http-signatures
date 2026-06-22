/**
 * Fixture-integrity check (NOT a library test).
 *
 * Verifies every RFC 9421 Appendix B signature vector against its published
 * signature base and key using the platform WebCrypto directly. If any value in
 * `test/fixtures/rfc9421-vectors.ts` was transcribed incorrectly, the relevant
 * verification fails here, independent of this library's own code.
 *
 * Run: pnpm --filter @interledger-aligned/http-message-signatures validate:fixtures
 */

import { webcrypto } from "node:crypto";
import {
  SIGNATURE_VECTORS,
  KEYS,
  type SignatureVector,
} from "../test/fixtures/rfc9421-vectors.js";

const { subtle } = webcrypto;
const te = new TextEncoder();

/** Copy into a fresh ArrayBuffer-backed view (satisfies WebCrypto BufferSource). */
function ab(src: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(src.byteLength);
  out.set(src);
  return out;
}

function pemToDer(pem: string): Uint8Array<ArrayBuffer> {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  return ab(new Uint8Array(Buffer.from(body, "base64")));
}

function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  return ab(new Uint8Array(Buffer.from(b64, "base64")));
}

async function importVerifyKey(v: SignatureVector): Promise<webcrypto.CryptoKey> {
  switch (v.algorithm) {
    case "rsa-pss-sha512": {
      const der = pemToDer(KEYS["test-key-rsa-pss"].public);
      return subtle.importKey("spki", der, { name: "RSA-PSS", hash: "SHA-512" }, false, [
        "verify",
      ]);
    }
    case "ecdsa-p256-sha256": {
      const der = pemToDer(KEYS["test-key-ecc-p256"].public);
      return subtle.importKey(
        "spki",
        der,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
    }
    case "ed25519": {
      const der = pemToDer(KEYS["test-key-ed25519"].public);
      return subtle.importKey("spki", der, { name: "Ed25519" }, false, ["verify"]);
    }
    case "hmac-sha256": {
      const raw = b64ToBytes(KEYS["test-shared-secret"].secretBase64);
      return subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, [
        "sign",
        "verify",
      ]);
    }
    default:
      throw new Error(`Unexpected algorithm for fixtures: ${v.algorithm}`);
  }
}

function verifyParams(
  v: SignatureVector,
): webcrypto.AlgorithmIdentifier | webcrypto.RsaPssParams | webcrypto.EcdsaParams {
  switch (v.algorithm) {
    case "rsa-pss-sha512":
      return { name: "RSA-PSS", saltLength: 64 };
    case "ecdsa-p256-sha256":
      return { name: "ECDSA", hash: "SHA-256" };
    case "ed25519":
      return { name: "Ed25519" };
    case "hmac-sha256":
      return { name: "HMAC" };
    default:
      throw new Error(`Unexpected algorithm: ${v.algorithm}`);
  }
}

async function run(): Promise<void> {
  let failures = 0;

  for (const v of SIGNATURE_VECTORS) {
    const key = await importVerifyKey(v);
    const base = ab(te.encode(v.signatureBase));
    const sig = b64ToBytes(v.signature);

    const ok = await subtle.verify(verifyParams(v), key, sig, base);
    if (!ok) {
      failures += 1;
      console.error(`✗ ${v.label} (${v.section}, ${v.algorithm}): signature did NOT verify`);
      continue;
    }

    // Deterministic algorithms can be re-derived byte-for-byte.
    if (v.deterministic && v.algorithm === "hmac-sha256") {
      const mac = new Uint8Array(await subtle.sign({ name: "HMAC" }, key, base));
      const recomputed = Buffer.from(mac).toString("base64");
      if (recomputed !== v.signature) {
        failures += 1;
        console.error(
          `✗ ${v.label}: recomputed HMAC ${recomputed} != published ${v.signature}`,
        );
        continue;
      }
    }
    if (v.deterministic && v.algorithm === "ed25519") {
      const priv = await subtle.importKey(
        "pkcs8",
        pemToDer(KEYS["test-key-ed25519"].private),
        { name: "Ed25519" },
        false,
        ["sign"],
      );
      const out = new Uint8Array(await subtle.sign({ name: "Ed25519" }, priv, base));
      const recomputed = Buffer.from(out).toString("base64");
      if (recomputed !== v.signature) {
        failures += 1;
        console.error(
          `✗ ${v.label}: recomputed Ed25519 ${recomputed} != published ${v.signature}`,
        );
        continue;
      }
    }

    console.log(`✓ ${v.label} (${v.section}, ${v.algorithm})${v.deterministic ? " [exact]" : ""}`);
  }

  if (failures > 0) {
    console.error(`\n${failures} fixture(s) failed integrity verification.`);
    process.exit(1);
  }
  console.log(`\nAll ${SIGNATURE_VECTORS.length} RFC 9421 vectors verified against published keys.`);
}

run().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
