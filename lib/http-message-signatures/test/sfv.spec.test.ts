/**
 * Suite 1 — Structured Field Values codec (RFC 8941).
 * Parse↔serialize idempotency, the exact serializations RFC 9421 uses, and
 * rejection of malformed input. RED until Layer 0 (Step 3) is implemented.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  Token,
  ByteSequence,
  Decimal,
  parseItem,
  parseList,
  parseDictionary,
  serializeItem,
  serializeList,
  serializeDictionary,
  type Item,
} from "../src/sfv.js";

function item(value: Item["value"], params: [string, Item["value"]][] = []): Item {
  return { value, params: new Map(params) };
}

describe("SFV: bare item round-trips (RFC 8941 §3.3)", () => {
  test("string preserves quotes and escaping; never coerced to token", () => {
    assert.equal(serializeItem(item("hello world")), '"hello world"');
    assert.equal(serializeItem(item('a"b\\c')), '"a\\"b\\\\c"');
    const parsed = parseItem('"hello"');
    assert.equal(typeof parsed.value, "string");
    assert.equal(parsed.value, "hello");
  });

  test("token serializes bare and parses to a Token (distinct from string)", () => {
    assert.equal(serializeItem(item(new Token("foo"))), "foo");
    const parsed = parseItem("foo");
    assert.ok(parsed.value instanceof Token);
    assert.equal((parsed.value as Token).value, "foo");
  });

  test("integer vs decimal are distinct (Amendment A1)", () => {
    assert.equal(serializeItem(item(42)), "42");
    assert.equal(serializeItem(item(new Decimal(4.5))), "4.5");
    const dec = parseItem("4.5");
    assert.ok(dec.value instanceof Decimal);
    const int = parseItem("42");
    assert.equal(int.value, 42);
    assert.equal(typeof int.value, "number");
  });

  test("byte sequence round-trips through base64 delimiters", () => {
    const bytes = new Uint8Array([1, 2, 3, 255]);
    assert.equal(serializeItem(item(new ByteSequence(bytes))), ":AQID/w==:");
    const parsed = parseItem(":AQID/w==:");
    assert.ok(parsed.value instanceof ByteSequence);
    assert.deepEqual([...(parsed.value as ByteSequence).bytes], [1, 2, 3, 255]);
  });

  test("boolean round-trips", () => {
    assert.equal(serializeItem(item(true)), "?1");
    assert.equal(serializeItem(item(false)), "?0");
    assert.equal(parseItem("?1").value, true);
  });
});

describe("SFV: lists and dictionaries (RFC 8941 §3.1/§3.2)", () => {
  test("dictionary preserves insertion order", () => {
    const dict = parseDictionary("a=1, b=2, c=3");
    assert.deepEqual([...dict.keys()], ["a", "b", "c"]);
    assert.equal(serializeDictionary(dict), "a=1, b=2, c=3");
  });

  test("list with inner list and parameters", () => {
    const list = parseList('("a" "b");x=1, "c"');
    assert.equal(serializeList(list), '("a" "b");x=1, "c"');
  });

  test("boolean dictionary members serialize without =?1", () => {
    const dict = parseDictionary("a, b=?0");
    assert.equal(serializeDictionary(dict), "a, b=?0");
  });
});

describe("SFV: malformed input is rejected (RFC 8941 §4.2)", () => {
  test("trailing junk after a complete parse throws", () => {
    assert.throws(() => parseItem("123 garbage"));
  });

  test("duplicate dictionary keys: last value wins per §4.2.2", () => {
    const dict = parseDictionary("a=1, a=2");
    assert.equal(serializeDictionary(dict), "a=2");
  });

  test("lone backslash escape in string throws", () => {
    assert.throws(() => parseItem('"bad\\escape"'));
  });

  test("decimal with more than three fractional digits throws", () => {
    assert.throws(() => parseItem("1.2345"));
  });

  test("bad base64 in byte sequence throws", () => {
    assert.throws(() => parseItem(":!!!notbase64:"));
  });
});
