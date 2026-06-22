/**
 * Suite 5 — End-to-end RFC 9421 Appendix B compliance.
 * Every published signature must verify through the library; deterministic
 * vectors (HMAC, Ed25519) must additionally be reproduced byte-for-byte.
 * RED until Layers 2–3 (Steps 5–7) are implemented.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { signMessage } from "../src/sign.js";
import { verifyMessage } from "../src/verify.js";
import type { ComponentSpec, HttpMessage, SignatureParameters } from "../src/types.js";
import {
  TEST_REQUEST,
  TEST_RESPONSE,
  PROXY_REQUEST,
  SIGNATURE_VECTORS,
  vectorByLabel,
  type SignatureVector,
} from "./fixtures/rfc9421-vectors.js";
import { fixtureSigningKey, fixtureVerifyingKey } from "./helpers/crypto.js";

const CREATED = 1618884473;

/** Pick the message a vector was produced over. */
function messageFor(v: SignatureVector): HttpMessage {
  if (v.label === "sig-b24") return TEST_RESPONSE;
  if (v.label === "ttrp") return PROXY_REQUEST;
  return TEST_REQUEST;
}

/** Attach the published Signature-Input/Signature headers to a base message. */
function signedMessage(v: SignatureVector): HttpMessage {
  const base = messageFor(v);
  return {
    ...base,
    headers: {
      ...base.headers,
      "signature-input": `${v.label}=${v.signatureInput}`,
      signature: `${v.label}=:${v.signature}:`,
    },
  };
}

describe("Appendix B — published signatures verify", () => {
  for (const v of SIGNATURE_VECTORS) {
    test(`${v.label} verifies (${v.section}, ${v.algorithm})`, async () => {
      const message = signedMessage(v);
      let seenKeyid: string | undefined;
      let lookupCalls = 0;
      const result = await verifyMessage(message, {
        keyLookup: async (keyid) => {
          seenKeyid = keyid;
          lookupCalls += 1;
          return fixtureVerifyingKey(v.algorithm, v.keyid);
        },
        now: () => CREATED,
      });
      assert.equal(result.valid, true);
      assert.equal(result.label, v.label);
      // The implementation must parse the keyid from Signature-Input and pass
      // it to keyLookup — verification must not ignore the advertised keyid.
      assert.equal(lookupCalls, 1);
      assert.equal(seenKeyid, v.keyid);
    });
  }
});

describe("Appendix B — deterministic vectors reproduce exactly", () => {
  test("sig-b25 (hmac-sha256) reproduces the published signature", async () => {
    const v = vectorByLabel("sig-b25");
    const components: ComponentSpec[] = ["date", "@authority", "content-type"];
    const params: SignatureParameters = { created: CREATED, keyid: v.keyid };
    const out = await signMessage(TEST_REQUEST, {
      key: await fixtureSigningKey("hmac-sha256", v.keyid),
      alg: "hmac-sha256",
      components,
      params,
      label: v.label,
    });
    assert.equal(out.signature, `${v.label}=:${v.signature}:`);
    assert.equal(out.signatureInput, `${v.label}=${v.signatureInput}`);
  });

  test("sig-b26 (ed25519) reproduces the published signature", async () => {
    const v = vectorByLabel("sig-b26");
    const components: ComponentSpec[] = [
      "date",
      "@method",
      "@path",
      "@authority",
      "content-type",
      "content-length",
    ];
    const params: SignatureParameters = { created: CREATED, keyid: v.keyid };
    const out = await signMessage(TEST_REQUEST, {
      key: await fixtureSigningKey("ed25519", v.keyid),
      alg: "ed25519",
      components,
      params,
      label: v.label,
    });
    assert.equal(out.signature, `${v.label}=:${v.signature}:`);
  });
});

describe("Appendix B — tampering is detected", () => {
  test("a flipped signature byte fails verification", async () => {
    const v = vectorByLabel("sig-b26");
    const message = signedMessage(v);
    const tampered: HttpMessage = {
      ...message,
      headers: {
        ...message.headers,
        date: "Tue, 20 Apr 2021 02:07:56 GMT",
      },
    };
    const result = await verifyMessage(tampered, {
      keyLookup: async () => fixtureVerifyingKey(v.algorithm, v.keyid),
      now: () => CREATED,
    });
    assert.equal(result.valid, false);
  });
});
