/**
 * Runnable end-to-end example (RFC 9421 §3.1–3.2, modeled on Appendix B.2).
 *
 * Generates an Ed25519 key with the Web Crypto API, signs a request over a set
 * of covered components, then verifies it under a strict policy (explicit
 * algorithm allow-list, required covered components, freshness window).
 *
 * Run from the package root:
 *   node --import tsx examples/sign-and-verify.ts
 *
 * In your own project, replace the relative import with the package name:
 *   import { signMessage, verifyMessage } from "@interledger-aligned/http-message-signatures";
 */

import { webcrypto } from "node:crypto";

import {
  signMessage,
  verifyMessage,
  type RequestLike,
  type SigningKey,
  type VerifyingKey,
} from "../src/index.js";

const ALG = "ed25519" as const;
const KEYID = "test-key-ed25519";

// 1. Key material. In production these come from your key store / JWKS; here we
//    generate an ephemeral pair so the example is self-contained.
const pair = (await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, [
  "sign",
  "verify",
])) as webcrypto.CryptoKeyPair;

const signingKey: SigningKey = {
  alg: ALG,
  keyid: KEYID,
  sign: async (data) => new Uint8Array(await webcrypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, data)),
};

const verifyingKey: VerifyingKey = {
  algs: [ALG],
  verify: (data, signature) => webcrypto.subtle.verify({ name: "Ed25519" }, pair.publicKey, signature, data),
};

// 2. The request to protect.
const request: RequestLike = {
  method: "POST",
  url: "https://example.com/foo?param=Value&Pet=dog",
  headers: {
    host: "example.com",
    date: "Tue, 20 Apr 2021 02:07:55 GMT",
    "content-type": "application/json",
  },
};

// 3. Sign. The algorithm is explicit (no insecure default) and `created` makes
//    the signature freshness-checkable.
const created = Math.floor(Date.now() / 1000);
const { signatureInput, signature } = await signMessage(request, {
  key: signingKey,
  components: ["@method", "@authority", "@path", "content-type"],
  params: { created, keyid: KEYID, alg: ALG },
});

console.log("Signature-Input:", signatureInput);
console.log("Signature:", signature);

// 4. The wire message the verifier receives.
const received: RequestLike = {
  ...request,
  headers: { ...request.headers, "signature-input": signatureInput, signature },
};

// 5. Verify under a strict policy.
const result = await verifyMessage(received, {
  keyLookup: (keyid, alg) => (keyid === KEYID && alg === ALG ? verifyingKey : null),
  policy: {
    allowedAlgorithms: [ALG],
    requiredCoveredComponents: ["@method", "@authority", "@path"],
    maxAgeSeconds: 300,
  },
});

console.log("Verification result:", result);

if (!result.valid) {
  throw new Error(`expected a valid signature, got: ${result.reason}`);
}
console.log("\nOK — signature is valid and satisfies the policy.");
