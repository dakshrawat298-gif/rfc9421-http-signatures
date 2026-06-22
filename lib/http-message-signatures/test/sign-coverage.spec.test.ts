/**
 * Coverage suite — signer key handling and parameter assembly (`src/sign.ts`).
 * Drives every branch: SigningKey vs raw CryptoKey, label defaulting, and the
 * keyid precedence rules (params.keyid > options.keyid > signing-key keyid).
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { signMessage } from "../src/sign.js";
import { UnsupportedAlgorithmError } from "../src/errors.js";
import type { ComponentSpec, CryptoKey } from "../src/types.js";
import { TEST_REQUEST } from "./fixtures/rfc9421-vectors.js";
import { generateSigner, generateRawSigningKey } from "./helpers/crypto.js";

const COMPONENTS: ComponentSpec[] = ["@method", "@authority", "@path"];

describe("signMessage: label handling", () => {
  test("defaults the label to 'sig' when none is supplied", async () => {
    const { signing } = await generateSigner("ed25519");
    const res = await signMessage(TEST_REQUEST, { key: signing, components: COMPONENTS });
    assert.ok(res.signatureInput.startsWith("sig="));
    assert.ok(res.signature.startsWith("sig="));
  });

  test("honors an explicit label", async () => {
    const { signing } = await generateSigner("ed25519");
    const res = await signMessage(TEST_REQUEST, {
      key: signing,
      components: COMPONENTS,
      label: "reqsig",
    });
    assert.ok(res.signatureInput.startsWith("reqsig="));
    assert.ok(res.signature.startsWith("reqsig="));
  });
});

describe("signMessage: keyid precedence", () => {
  test("uses the signing key's keyid when nothing overrides it", async () => {
    const { signing } = await generateSigner("ed25519", "key-from-signer");
    const res = await signMessage(TEST_REQUEST, {
      key: signing,
      components: COMPONENTS,
      params: { created: 1 },
    });
    assert.match(res.signatureInput, /keyid="key-from-signer"/);
  });

  test("options.keyid overrides the signing key's keyid", async () => {
    const { signing } = await generateSigner("ed25519", "key-from-signer");
    const res = await signMessage(TEST_REQUEST, {
      key: signing,
      components: COMPONENTS,
      keyid: "override-keyid",
      params: { created: 1 },
    });
    assert.match(res.signatureInput, /keyid="override-keyid"/);
  });

  test("an explicit params.keyid is preserved verbatim", async () => {
    const { signing } = await generateSigner("ed25519", "key-from-signer");
    const res = await signMessage(TEST_REQUEST, {
      key: signing,
      components: COMPONENTS,
      keyid: "ignored",
      params: { created: 1, keyid: "param-keyid" },
    });
    assert.match(res.signatureInput, /keyid="param-keyid"/);
  });

  test("emits no keyid when none is available anywhere", async () => {
    const { signing } = await generateSigner("ed25519");
    const res = await signMessage(TEST_REQUEST, {
      key: signing,
      components: COMPONENTS,
      params: { created: 1 },
    });
    assert.doesNotMatch(res.signatureInput, /keyid=/);
  });
});

describe("signMessage: raw CryptoKey path", () => {
  test("signs with a raw CryptoKey when an explicit alg is given", async () => {
    const raw = await generateRawSigningKey("ecdsa-p256-sha256");
    const res = await signMessage(TEST_REQUEST, {
      key: raw,
      alg: "ecdsa-p256-sha256",
      components: COMPONENTS,
      params: { created: 1, keyid: "k1" },
    });
    assert.ok(res.signature.startsWith("sig="));
    assert.match(res.signatureInput, /keyid="k1"/);
  });

  test("rejects a raw CryptoKey with no explicit alg (no insecure default)", async () => {
    const raw = await generateRawSigningKey("ed25519");
    await assert.rejects(
      signMessage(TEST_REQUEST, { key: raw, components: COMPONENTS }),
      UnsupportedAlgorithmError,
    );
  });

  test("an object with sign() but no `alg` is treated as a raw key, not a SigningKey", async () => {
    // isSigningKey requires BOTH a sign() function AND an `alg` field; this
    // object has the former but not the latter, so it falls to the raw-key path
    // (which then fails inside WebCrypto because it is not a real CryptoKey).
    const fake = { sign: () => new Uint8Array(8) } as unknown as CryptoKey;
    await assert.rejects(
      signMessage(TEST_REQUEST, { key: fake, alg: "ed25519", components: COMPONENTS }),
    );
  });
});
