/**
 * Coverage suite — signature base construction (`src/base.ts`).
 * Exercises every derived component, every field-parameter mode (sf/bs/key),
 * the ;req related-request path, and each UnsupportedComponentError branch.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  createSignatureBase,
  componentId,
  coveredComponentId,
} from "../src/base.js";
import { UnsupportedComponentError } from "../src/errors.js";
import type {
  ComponentSpec,
  HttpMessage,
  RequestLike,
  ResponseLike,
} from "../src/types.js";

const CREATED = 1618884473;
const REQ: RequestLike = {
  method: "post",
  url: "https://Example.COM:443/foo/bar?b=2&a=1&a=3",
  headers: {
    "x-dict": "a=1, b=2",
    "x-multi": ["one", "two"],
    "content-type": "application/json",
  },
};

function lineFor(message: HttpMessage, spec: ComponentSpec): string {
  return createSignatureBase(message, [spec], { created: CREATED }).split("\n")[0]!;
}

describe("derived components", () => {
  const expectations: [ComponentSpec, string][] = [
    ["@method", '"@method": POST'],
    ["@target-uri", '"@target-uri": https://example.com/foo/bar?b=2&a=1&a=3'],
    ["@authority", '"@authority": example.com'],
    ["@scheme", '"@scheme": https'],
    ["@request-target", '"@request-target": /foo/bar?b=2&a=1&a=3'],
    ["@path", '"@path": /foo/bar'],
    ["@query", '"@query": ?b=2&a=1&a=3'],
  ];
  for (const [spec, expected] of expectations) {
    test(`${String(spec)} renders canonically`, () => {
      assert.equal(lineFor(REQ, spec), expected);
    });
  }

  test("@query with no query string yields '?'", () => {
    assert.equal(
      lineFor({ ...REQ, url: "https://example.com/foo" }, "@query"),
      '"@query": ?',
    );
  });

  test("@query-param keeps the first occurrence of a repeated name", () => {
    assert.equal(lineFor(REQ, { name: "@query-param", params: { name: "a" } }), '"@query-param";name="a": 1');
  });

  test("@query-param without a name parameter is rejected", () => {
    assert.throws(
      () => lineFor(REQ, { name: "@query-param", params: {} }),
      UnsupportedComponentError,
    );
  });

  test("an unknown derived component is rejected", () => {
    assert.throws(() => lineFor(REQ, "@bogus"), UnsupportedComponentError);
  });

  test("a derived component on a request-less message is rejected", () => {
    const response: ResponseLike = { status: 200, headers: {} };
    assert.throws(() => lineFor(response, "@path"), UnsupportedComponentError);
  });
});

describe("@status and the ;req related-request path", () => {
  test("@status renders on a response", () => {
    const response: ResponseLike = { status: 503, headers: {} };
    assert.equal(lineFor(response, "@status"), '"@status": 503');
  });

  test("@status on a request is rejected", () => {
    assert.throws(() => lineFor(REQ, "@status"), UnsupportedComponentError);
  });

  test(";req resolves a derived component against the related request", () => {
    const response: ResponseLike = { status: 200, headers: {}, relatedRequest: REQ };
    assert.equal(lineFor(response, { name: "@method", params: { req: true } }), '"@method";req: POST');
  });

  test(";req without a related request is rejected", () => {
    const response: ResponseLike = { status: 200, headers: {} };
    assert.throws(
      () => lineFor(response, { name: "@method", params: { req: true } }),
      UnsupportedComponentError,
    );
  });
});

describe("field components and parameters", () => {
  test("a plain field uses the trimmed value", () => {
    assert.equal(lineFor(REQ, "content-type"), '"content-type": application/json');
  });

  test("multiple field values are combined with ', '", () => {
    assert.equal(lineFor(REQ, "x-multi"), '"x-multi": one, two');
  });

  test("a missing field is rejected", () => {
    assert.throws(() => lineFor(REQ, "x-absent"), UnsupportedComponentError);
  });

  test(";bs emits a byte-sequence wrapping", () => {
    assert.equal(
      lineFor(REQ, { name: "content-type", params: { bs: true } }),
      '"content-type";bs: :YXBwbGljYXRpb24vanNvbg==:',
    );
  });

  test(";sf re-serializes a structured dictionary", () => {
    assert.equal(lineFor(REQ, { name: "x-dict", params: { sf: true } }), '"x-dict";sf: a=1, b=2');
  });

  test(";sf re-serializes a structured list when the field is not a dictionary", () => {
    const msg = { ...REQ, headers: { ...REQ.headers, "x-list": "1,  2,    3" } };
    assert.equal(lineFor(msg, { name: "x-list", params: { sf: true } }), '"x-list";sf: 1, 2, 3');
  });

  test(";tr marks a component as a trailer", () => {
    assert.equal(lineFor(REQ, { name: "x-multi", params: { tr: true } }), '"x-multi";tr: one, two');
  });

  test(";key selects a dictionary member", () => {
    assert.equal(lineFor(REQ, { name: "x-dict", params: { key: "b" } }), '"x-dict";key="b": 2');
  });

  test(";key for a missing member is rejected", () => {
    assert.throws(
      () => lineFor(REQ, { name: "x-dict", params: { key: "zzz" } }),
      UnsupportedComponentError,
    );
  });

  test(";key with a non-string key is rejected", () => {
    assert.throws(
      () => lineFor(REQ, { name: "x-dict", params: { key: 5 as unknown as string } }),
      UnsupportedComponentError,
    );
  });
});

describe("component identifier serializers", () => {
  test("componentId quotes the name and serializes parameters", () => {
    assert.equal(
      componentId({ value: "@query-param", params: new Map([["name", "q"]]) }),
      '"@query-param";name="q"',
    );
  });

  test("coveredComponentId leaves the bare name unquoted", () => {
    assert.equal(
      coveredComponentId({ value: "@method", params: new Map([["req", true]]) }),
      "@method;req",
    );
  });
});
