/**
 * Suite 3 — HTTP field components (RFC 9421 §2.1).
 * Canonicalization: lowercasing, OWS trimming, multi-value combining, and the
 * sf/bs/key/req parameters. RED until Layer 1 (Step 4) is implemented.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { createSignatureBase } from "../src/sign.js";
import type { ComponentSpec, HttpMessage } from "../src/types.js";
import { TEST_REQUEST, TEST_RESPONSE, REQUEST_CONTENT_DIGEST } from "./fixtures/rfc9421-vectors.js";

function firstLine(message: HttpMessage, component: ComponentSpec): string {
  return createSignatureBase(message, [component], {}).split("\n")[0] ?? "";
}

describe("field canonicalization (RFC 9421 §2.1)", () => {
  test("plain field value", () => {
    assert.equal(firstLine(TEST_REQUEST, "date"), '"date": Tue, 20 Apr 2021 02:07:55 GMT');
  });

  test("content-digest carries its structured value verbatim", () => {
    assert.equal(
      firstLine(TEST_REQUEST, "content-digest"),
      `"content-digest": ${REQUEST_CONTENT_DIGEST}`,
    );
  });

  test("component name is lowercased (§2.1)", () => {
    assert.equal(firstLine(TEST_REQUEST, "Content-Type"), '"content-type": application/json');
  });

  test("leading/trailing OWS is stripped and inner runs preserved", () => {
    const msg: HttpMessage = {
      method: "GET",
      url: "https://example.com/",
      headers: { "x-ows": "   value   " },
    };
    assert.equal(firstLine(msg, "x-ows"), '"x-ows": value');
  });

  test("multiple field values are combined with comma-space (§2.1)", () => {
    const msg: HttpMessage = {
      method: "GET",
      url: "https://example.com/",
      headers: { "x-multi": ["a", "b", "c"] },
    };
    assert.equal(firstLine(msg, "x-multi"), '"x-multi": a, b, c');
  });

  test("missing field throws (no silent empty value)", () => {
    const msg: HttpMessage = { method: "GET", url: "https://example.com/", headers: {} };
    assert.throws(() => createSignatureBase(msg, ["x-absent"], {}));
  });
});

describe("field parameters (RFC 9421 §2.1.1–§2.1.3)", () => {
  test("sf re-serializes a structured dictionary canonically", () => {
    const msg: HttpMessage = {
      method: "GET",
      url: "https://example.com/",
      headers: { "example-dict": "a=1,    b=2;x=1;y=2,   c=(a   b   c)" },
    };
    assert.equal(
      firstLine(msg, { name: "example-dict", params: { sf: true } }),
      '"example-dict";sf: a=1, b=2;x=1;y=2, c=(a b c)',
    );
  });

  test("key selects a single dictionary member", () => {
    const msg: HttpMessage = {
      method: "GET",
      url: "https://example.com/",
      headers: { "example-dict": "a=1, b=2, c=3" },
    };
    assert.equal(
      firstLine(msg, { name: "example-dict", params: { key: "b" } }),
      '"example-dict";key="b": 2',
    );
  });

  test("bs wraps each field line as a byte sequence", () => {
    const value = "value";
    const expected = `:${Buffer.from(value).toString("base64")}:`;
    const msg: HttpMessage = {
      method: "GET",
      url: "https://example.com/",
      headers: { "x-bs": value },
    };
    assert.equal(firstLine(msg, { name: "x-bs", params: { bs: true } }), `"x-bs";bs: ${expected}`);
  });
});

describe("req parameter binds a response to its request (RFC 9421 §2.4)", () => {
  test("@authority;req on a response uses the related request", () => {
    const response: HttpMessage = { ...TEST_RESPONSE, relatedRequest: TEST_REQUEST };
    const line = createSignatureBase(
      response,
      [{ name: "@authority", params: { req: true } }],
      {},
    ).split("\n")[0];
    assert.equal(line, '"@authority";req: example.com');
  });
});
