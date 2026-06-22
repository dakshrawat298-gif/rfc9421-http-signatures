/**
 * Suite 2 — Derived components (RFC 9421 §2.2).
 * One assertion per derived component, computed via createSignatureBase over the
 * Appendix B fixtures. RED until Layer 1 (Step 4) is implemented.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { createSignatureBase } from "../src/sign.js";
import type { ComponentSpec, HttpMessage } from "../src/types.js";
import { TEST_REQUEST, TEST_RESPONSE } from "./fixtures/rfc9421-vectors.js";

function firstLine(message: HttpMessage, component: ComponentSpec): string {
  const base = createSignatureBase(message, [component], {});
  return base.split("\n")[0] ?? "";
}

describe("derived components from test-request (RFC 9421 §2.2)", () => {
  const cases: Array<[ComponentSpec, string]> = [
    ["@method", '"@method": POST'],
    ["@target-uri", '"@target-uri": https://example.com/foo?param=Value&Pet=dog'],
    ["@authority", '"@authority": example.com'],
    ["@scheme", '"@scheme": https'],
    ["@request-target", '"@request-target": /foo?param=Value&Pet=dog'],
    ["@path", '"@path": /foo'],
    ["@query", '"@query": ?param=Value&Pet=dog'],
    [{ name: "@query-param", params: { name: "Pet" } }, '"@query-param";name="Pet": dog'],
    [{ name: "@query-param", params: { name: "param" } }, '"@query-param";name="param": Value'],
  ];

  for (const [component, expected] of cases) {
    const label = typeof component === "string" ? component : `${component.name};name`;
    test(label, () => {
      assert.equal(firstLine(TEST_REQUEST, component), expected);
    });
  }
});

describe("derived components from test-response (RFC 9421 §2.2.9)", () => {
  test("@status", () => {
    assert.equal(firstLine(TEST_RESPONSE, "@status"), '"@status": 200');
  });
});

describe("derived component edge cases (RFC 9421 §2.2)", () => {
  test("empty query serializes as a lone ?", () => {
    const msg: HttpMessage = {
      method: "GET",
      url: "https://example.com/path",
      headers: {},
    };
    assert.equal(firstLine(msg, "@query"), '"@query": ?');
  });

  test("default https port is omitted from @authority", () => {
    const msg: HttpMessage = {
      method: "GET",
      url: "https://example.com:443/",
      headers: {},
    };
    assert.equal(firstLine(msg, "@authority"), '"@authority": example.com');
  });

  test("@status is illegal on a request", () => {
    assert.throws(() => createSignatureBase(TEST_REQUEST, ["@status"], {}));
  });
});
