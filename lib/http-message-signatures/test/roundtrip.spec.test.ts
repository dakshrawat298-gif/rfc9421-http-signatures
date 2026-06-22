/**
 * Suite 6 — Sign→verify round-trips for every supported algorithm, including
 * those without RFC fixtures (ECDSA P-384, RSA-v1_5). Uses ephemeral keys.
 * RED until Layers 2–3 (Steps 5–7) are implemented.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { signMessage } from "../src/sign.js";
import { verifyMessage } from "../src/verify.js";
import type { ComponentSpec, SignatureAlgorithm, SignatureParameters } from "../src/types.js";
import { TEST_REQUEST } from "./fixtures/rfc9421-vectors.js";
import { generateSigner } from "./helpers/crypto.js";

const ALGS: SignatureAlgorithm[] = [
  "rsa-pss-sha512",
  "rsa-v1_5-sha256",
  "ecdsa-p256-sha256",
  "ecdsa-p384-sha384",
  "ed25519",
  "hmac-sha256",
];

const COMPONENTS: ComponentSpec[] = ["@method", "@authority", "@path", "content-type", "date"];
const CREATED = 1618884473;

describe("round-trip across all algorithms", () => {
  for (const alg of ALGS) {
    test(`${alg}: sign then verify is valid`, async () => {
      const { signing, verifying } = await generateSigner(alg, "k1");
      const params: SignatureParameters = { created: CREATED, keyid: "k1" };
      const signed = await signMessage(TEST_REQUEST, {
        key: signing,
        alg,
        components: COMPONENTS,
        params,
        label: "sig",
      });
      const message = {
        ...TEST_REQUEST,
        headers: {
          ...TEST_REQUEST.headers,
          "signature-input": signed.signatureInput.replace(/^sig=/, "sig="),
          signature: signed.signature,
        },
      };
      const result = await verifyMessage(message, {
        keyLookup: async () => verifying,
        now: () => CREATED,
      });
      assert.equal(result.valid, true);
      assert.deepEqual(result.coveredComponents, COMPONENTS);
    });

    test(`${alg}: a different key fails verification`, async () => {
      const { signing } = await generateSigner(alg, "k1");
      const { verifying: otherKey } = await generateSigner(alg, "k1");
      const params: SignatureParameters = { created: CREATED, keyid: "k1" };
      const signed = await signMessage(TEST_REQUEST, {
        key: signing,
        alg,
        components: COMPONENTS,
        params,
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
        keyLookup: async () => otherKey,
        now: () => CREATED,
      });
      assert.equal(result.valid, false);
    });
  }
});
