/**
 * Coverage suite — algorithm registry (`src/crypto.ts`).
 * Exercises every registered identifier plus the rejection paths.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  SUPPORTED_ALGORITHMS,
  isSupportedAlgorithm,
  webcryptoSignParams,
} from "../src/crypto.js";
import { UnsupportedAlgorithmError } from "../src/errors.js";
import type { SignatureAlgorithm } from "../src/types.js";

describe("crypto: algorithm registry", () => {
  test("isSupportedAlgorithm accepts every registered identifier", () => {
    for (const alg of SUPPORTED_ALGORITHMS) {
      assert.equal(isSupportedAlgorithm(alg), true);
    }
  });

  test("isSupportedAlgorithm rejects unknown identifiers", () => {
    assert.equal(isSupportedAlgorithm("rsa-pkcs1-md5"), false);
    assert.equal(isSupportedAlgorithm(""), false);
    assert.equal(isSupportedAlgorithm("ED25519"), false);
  });

  test("webcryptoSignParams maps every registered algorithm", () => {
    assert.deepEqual(webcryptoSignParams("rsa-pss-sha512"), { name: "RSA-PSS", saltLength: 64 });
    assert.deepEqual(webcryptoSignParams("rsa-v1_5-sha256"), { name: "RSASSA-PKCS1-v1_5" });
    assert.deepEqual(webcryptoSignParams("ecdsa-p256-sha256"), { name: "ECDSA", hash: "SHA-256" });
    assert.deepEqual(webcryptoSignParams("ecdsa-p384-sha384"), { name: "ECDSA", hash: "SHA-384" });
    assert.deepEqual(webcryptoSignParams("ed25519"), { name: "Ed25519" });
    assert.deepEqual(webcryptoSignParams("hmac-sha256"), { name: "HMAC" });
  });

  test("webcryptoSignParams throws on an unregistered algorithm", () => {
    assert.throws(
      () => webcryptoSignParams("bogus-alg" as SignatureAlgorithm),
      UnsupportedAlgorithmError,
    );
  });
});
