/**
 * Suite 8 — Public API surface and error taxonomy.
 * Entry points are exported and tree-shakeable; every error is runtime
 * discriminable via a stable `code`. Most of this suite is GREEN once the
 * scaffold compiles; signing/verifying behaviour stays RED until Steps 5–7.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import * as root from "../src/index.js";
import { signMessage, createSignatureBase } from "../src/sign.js";
import { verifyMessage } from "../src/verify.js";
import {
  SignatureError,
  MalformedMessageError,
  MalformedSignatureError,
  UnsupportedAlgorithmError,
  UnsupportedComponentError,
  KeyResolutionError,
  PolicyViolationError,
  VerificationFailedError,
} from "../src/errors.js";

describe("public entry points", () => {
  test("root barrel re-exports the high-level API", () => {
    assert.equal(typeof root.signMessage, "function");
    assert.equal(typeof root.verifyMessage, "function");
    assert.equal(typeof root.createSignatureBase, "function");
  });

  test("subpath modules expose their functions", () => {
    assert.equal(typeof signMessage, "function");
    assert.equal(typeof verifyMessage, "function");
    assert.equal(typeof createSignatureBase, "function");
  });
});

describe("error taxonomy is runtime-discriminable", () => {
  const cases: Array<[new (msg: string) => SignatureError, string]> = [
    [MalformedMessageError, "ERR_MALFORMED_MESSAGE"],
    [MalformedSignatureError, "ERR_MALFORMED_SIGNATURE"],
    [UnsupportedAlgorithmError, "ERR_UNSUPPORTED_ALGORITHM"],
    [UnsupportedComponentError, "ERR_UNSUPPORTED_COMPONENT"],
    [KeyResolutionError, "ERR_KEY_RESOLUTION"],
    [PolicyViolationError, "ERR_POLICY_VIOLATION"],
    [VerificationFailedError, "ERR_VERIFICATION_FAILED"],
  ];

  for (const [Ctor, code] of cases) {
    test(`${Ctor.name} → ${code}`, () => {
      const err = new Ctor("boom");
      assert.ok(err instanceof SignatureError);
      assert.ok(err instanceof Error);
      assert.equal(err.code, code);
      assert.equal(err.message, "boom");
      assert.equal(err.name, Ctor.name);
    });
  }

  test("codes are unique across the taxonomy", () => {
    const codes = cases.map(([, code]) => code);
    assert.equal(new Set(codes).size, codes.length);
  });
});
