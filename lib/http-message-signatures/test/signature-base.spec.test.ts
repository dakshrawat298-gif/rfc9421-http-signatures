/**
 * Suite 4 — Signature base construction (RFC 9421 §2.5).
 * Reconstructs the worked example (Figure 1) and every Appendix B base
 * byte-for-byte. RED until Layer 1 (Step 4) is implemented.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { createSignatureBase } from "../src/sign.js";
import type { ComponentSpec, SignatureParameters } from "../src/types.js";
import {
  TEST_REQUEST,
  TEST_RESPONSE,
  PROXY_REQUEST,
  SECTION_2_5_SIGNATURE_BASE,
  SIGNATURE_VECTORS,
  vectorByLabel,
} from "./fixtures/rfc9421-vectors.js";

const CREATED = 1618884473;

describe("signature base (RFC 9421 §2.5)", () => {
  test("reconstructs the §2.5 worked example (Figure 1) exactly", () => {
    const components: ComponentSpec[] = [
      "@method",
      "@authority",
      "@path",
      "content-digest",
      "content-length",
      "content-type",
    ];
    const params: SignatureParameters = { created: CREATED, keyid: "test-key-rsa-pss" };
    assert.equal(
      createSignatureBase(TEST_REQUEST, components, params),
      SECTION_2_5_SIGNATURE_BASE,
    );
  });

  test("no trailing newline is appended (§2.5)", () => {
    const base = createSignatureBase(TEST_REQUEST, ["@method"], {
      created: CREATED,
      keyid: "k",
    });
    assert.equal(base.endsWith("\n"), false);
  });

  test("the @signature-params line is always last", () => {
    const base = createSignatureBase(TEST_REQUEST, ["@method", "date"], {
      created: CREATED,
      keyid: "k",
    });
    const lines = base.split("\n");
    assert.ok(lines[lines.length - 1]?.startsWith('"@signature-params":'));
  });
});

describe("Appendix B signature bases reconstruct byte-for-byte", () => {
  // Map each vector to (message, components, params) and rebuild its base.
  const b21 = vectorByLabel("sig-b21");
  test(`${b21.label} — empty component set (${b21.section})`, () => {
    const params: SignatureParameters = {
      created: CREATED,
      keyid: "test-key-rsa-pss",
      nonce: "b3k2pp5k7z-50gnwp.yemd",
    };
    assert.equal(createSignatureBase(TEST_REQUEST, [], params), b21.signatureBase);
  });

  const b22 = vectorByLabel("sig-b22");
  test(`${b22.label} — selective components + tag (${b22.section})`, () => {
    const components: ComponentSpec[] = [
      "@authority",
      "content-digest",
      { name: "@query-param", params: { name: "Pet" } },
    ];
    const params: SignatureParameters = {
      created: CREATED,
      keyid: "test-key-rsa-pss",
      tag: "header-example",
    };
    assert.equal(createSignatureBase(TEST_REQUEST, components, params), b22.signatureBase);
  });

  const b23 = vectorByLabel("sig-b23");
  test(`${b23.label} — full coverage (${b23.section})`, () => {
    const components: ComponentSpec[] = [
      "date",
      "@method",
      "@path",
      "@query",
      "@authority",
      "content-type",
      "content-digest",
      "content-length",
    ];
    const params: SignatureParameters = { created: CREATED, keyid: "test-key-rsa-pss" };
    assert.equal(createSignatureBase(TEST_REQUEST, components, params), b23.signatureBase);
  });

  const b24 = vectorByLabel("sig-b24");
  test(`${b24.label} — response with ecdsa (${b24.section})`, () => {
    const components: ComponentSpec[] = [
      "@status",
      "content-type",
      "content-digest",
      "content-length",
    ];
    const params: SignatureParameters = { created: CREATED, keyid: "test-key-ecc-p256" };
    assert.equal(createSignatureBase(TEST_RESPONSE, components, params), b24.signatureBase);
  });

  const b25 = vectorByLabel("sig-b25");
  test(`${b25.label} — hmac request (${b25.section})`, () => {
    const components: ComponentSpec[] = ["date", "@authority", "content-type"];
    const params: SignatureParameters = { created: CREATED, keyid: "test-shared-secret" };
    assert.equal(createSignatureBase(TEST_REQUEST, components, params), b25.signatureBase);
  });

  const b26 = vectorByLabel("sig-b26");
  test(`${b26.label} — ed25519 request (${b26.section})`, () => {
    const components: ComponentSpec[] = [
      "date",
      "@method",
      "@path",
      "@authority",
      "content-type",
      "content-length",
    ];
    const params: SignatureParameters = { created: CREATED, keyid: "test-key-ed25519" };
    assert.equal(createSignatureBase(TEST_REQUEST, components, params), b26.signatureBase);
  });

  const ttrp = vectorByLabel("ttrp");
  test(`${ttrp.label} — proxy client-cert (${ttrp.section})`, () => {
    const components: ComponentSpec[] = [
      "@path",
      "@query",
      "@method",
      "@authority",
      "client-cert",
    ];
    const params: SignatureParameters = { created: CREATED, keyid: "test-key-ecc-p256" };
    assert.equal(createSignatureBase(PROXY_REQUEST, components, params), ttrp.signatureBase);
  });

  test("all vectors are exercised", () => {
    assert.equal(SIGNATURE_VECTORS.length, 7);
  });
});
