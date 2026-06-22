/**
 * Suite 7 — Security policy and negative cases (RFC 9421 §7).
 * No insecure defaults, algorithm-confusion resistance, replay/expiry windows,
 * and required-component policy enforcement. RED until Layer 3 (Step 7).
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { signMessage } from "../src/sign.js";
import { verifyMessage } from "../src/verify.js";
import {
  MalformedSignatureError,
  UnsupportedAlgorithmError,
} from "../src/errors.js";
import type { ComponentSpec } from "../src/types.js";
import { TEST_REQUEST, vectorByLabel } from "./fixtures/rfc9421-vectors.js";
import { fixtureVerifyingKey, generateSigner, generateRawSigningKey } from "./helpers/crypto.js";

const CREATED = 1618884473;
const COMPONENTS: ComponentSpec[] = ["@method", "@authority", "@path"];

function signedHeaders(signatureInput: string, signature: string) {
  return {
    ...TEST_REQUEST.headers,
    "signature-input": signatureInput,
    signature,
  };
}

describe("no insecure defaults (RFC 9421 §7.3)", () => {
  test("signing with a raw CryptoKey but no algorithm is rejected", async () => {
    const rawKey = await generateRawSigningKey("ed25519");
    await assert.rejects(
      signMessage(TEST_REQUEST, {
        key: rawKey,
        components: COMPONENTS,
        params: { created: CREATED, keyid: "k1" },
        label: "sig",
      }),
    );
  });

  test("verification requires a key; an unknown keyid is rejected", async () => {
    const v = vectorByLabel("sig-b26");
    const message = {
      ...TEST_REQUEST,
      headers: signedHeaders(`${v.label}=${v.signatureInput}`, `${v.label}=:${v.signature}:`),
    };
    const result = await verifyMessage(message, {
      keyLookup: async () => null,
      now: () => CREATED,
    });
    assert.equal(result.valid, false);
  });
});

describe("algorithm confusion is resisted (RFC 9421 §7.3.6)", () => {
  test("a key that does not allow the message's alg fails", async () => {
    const v = vectorByLabel("sig-b26");
    const message = {
      ...TEST_REQUEST,
      headers: signedHeaders(`${v.label}=${v.signatureInput}`, `${v.label}=:${v.signature}:`),
    };
    // Offer an HMAC key where the message declares ed25519.
    const result = await verifyMessage(message, {
      keyLookup: async () => fixtureVerifyingKey("hmac-sha256", "test-shared-secret"),
      now: () => CREATED,
    });
    assert.equal(result.valid, false);
  });

  test("an unsupported alg token in Signature-Input is rejected", async () => {
    const message = {
      ...TEST_REQUEST,
      headers: signedHeaders(
        'sig=("@method");created=1618884473;keyid="k";alg="rsa-pkcs1-md5"',
        "sig=:AAAA:",
      ),
    };
    await assert.rejects(
      verifyMessage(message, { keyLookup: async () => generateSignerVerifying() }),
      UnsupportedAlgorithmError,
    );
  });
});

async function generateSignerVerifying() {
  return (await generateSigner("ed25519", "k")).verifying;
}

describe("expiry and replay windows (RFC 9421 §7.2)", () => {
  test("an expired signature (past expires) is rejected", async () => {
    const v = vectorByLabel("sig-b26");
    const message = {
      ...TEST_REQUEST,
      headers: signedHeaders(`${v.label}=${v.signatureInput}`, `${v.label}=:${v.signature}:`),
    };
    const result = await verifyMessage(message, {
      keyLookup: async () => fixtureVerifyingKey(v.algorithm, v.keyid),
      now: () => CREATED + 100000,
      policy: { maxAgeSeconds: 300 },
    });
    assert.equal(result.valid, false);
  });

  test("created in the future beyond tolerance is rejected", async () => {
    const v = vectorByLabel("sig-b26");
    const message = {
      ...TEST_REQUEST,
      headers: signedHeaders(`${v.label}=${v.signatureInput}`, `${v.label}=:${v.signature}:`),
    };
    const result = await verifyMessage(message, {
      keyLookup: async () => fixtureVerifyingKey(v.algorithm, v.keyid),
      now: () => CREATED - 100000,
    });
    assert.equal(result.valid, false);
  });
});

describe("required-component policy (RFC 9421 §7.2.2)", () => {
  test("missing a required covered component fails the policy", async () => {
    const v = vectorByLabel("sig-b26");
    const message = {
      ...TEST_REQUEST,
      headers: signedHeaders(`${v.label}=${v.signatureInput}`, `${v.label}=:${v.signature}:`),
    };
    const result = await verifyMessage(message, {
      keyLookup: async () => fixtureVerifyingKey(v.algorithm, v.keyid),
      now: () => CREATED,
      policy: { requiredCoveredComponents: ["@target-uri"] },
    });
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /required|component/i);
  });
});

describe("malformed signature headers (RFC 9421 §3.2)", () => {
  test("Signature without a matching Signature-Input throws", async () => {
    const message = {
      ...TEST_REQUEST,
      headers: { ...TEST_REQUEST.headers, signature: "sig=:AAAA:" },
    };
    await assert.rejects(
      verifyMessage(message, { keyLookup: async () => generateSignerVerifying() }),
      MalformedSignatureError,
    );
  });

  test("a non-byte-sequence Signature value throws", async () => {
    const message = {
      ...TEST_REQUEST,
      headers: signedHeaders('sig=("@method");created=1618884473;keyid="k"', "sig=not-a-byteseq"),
    };
    await assert.rejects(
      verifyMessage(message, { keyLookup: async () => generateSignerVerifying() }),
      MalformedSignatureError,
    );
  });
});
