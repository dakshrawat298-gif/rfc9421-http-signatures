/**
 * Suite 9 — Raw WebCrypto `CryptoKey` round-trips for every registered
 * algorithm. Signing uses the raw-key path of {@link signMessage} (explicit
 * `alg`, no SigningKey adapter); verification uses the library-owned
 * {@link createVerifyingKey}, so both the signing and verifying crypto
 * primitives are enforced inside the library rather than by caller boilerplate.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

import { signMessage } from "../src/sign.js";
import { verifyMessage, createVerifyingKey } from "../src/verify.js";
import type { SignatureAlgorithm, VerifyingKey } from "../src/types.js";
import { TEST_REQUEST } from "./fixtures/rfc9421-vectors.js";

const { subtle } = webcrypto;
const CREATED = 1618884473;
const COMPONENTS = ["@method", "@authority", "@path", "content-type", "date"] as const;

const ALGS: SignatureAlgorithm[] = [
  "rsa-pss-sha512",
  "rsa-v1_5-sha256",
  "ecdsa-p256-sha256",
  "ecdsa-p384-sha384",
  "ed25519",
  "hmac-sha256",
];

function genParams(alg: SignatureAlgorithm): webcrypto.RsaHashedKeyGenParams | webcrypto.EcKeyGenParams | webcrypto.HmacKeyGenParams | webcrypto.AlgorithmIdentifier {
  switch (alg) {
    case "rsa-pss-sha512":
      return { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-512" };
    case "rsa-v1_5-sha256":
      return { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
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

describe("signing with a raw CryptoKey + explicit alg", () => {
  for (const alg of ALGS) {
    test(`${alg}: raw key signs and round-trips`, async () => {
      let signingKey: webcrypto.CryptoKey;
      let verifying: VerifyingKey;
      if (alg === "hmac-sha256") {
        const k = (await subtle.generateKey(genParams(alg), true, ["sign", "verify"])) as webcrypto.CryptoKey;
        signingKey = k;
        verifying = createVerifyingKey(k, alg);
      } else {
        const pair = (await subtle.generateKey(genParams(alg), true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
        signingKey = pair.privateKey;
        verifying = createVerifyingKey(pair.publicKey, alg);
      }

      const signed = await signMessage(TEST_REQUEST, {
        key: signingKey,
        alg,
        components: [...COMPONENTS],
        params: { created: CREATED, keyid: "k1" },
        label: "sig",
      });

      const message = {
        ...TEST_REQUEST,
        headers: {
          ...TEST_REQUEST.headers,
          "signature-input": signed.signatureInput,
          signature: signed.signature,
        },
      };
      const result = await verifyMessage(message, {
        keyLookup: async () => verifying,
        now: () => CREATED,
      });
      assert.equal(result.valid, true);
    });
  }
});
