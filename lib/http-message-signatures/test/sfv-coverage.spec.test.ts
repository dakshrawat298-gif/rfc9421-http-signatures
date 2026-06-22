/**
 * Coverage suite — Structured Field Values codec (`src/sfv.ts`).
 * Targets every parser error branch, every serializer branch, and the accepted
 * edge cases (negative numbers, '*' keys, ':'/'/' tokens, inner-list params).
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  Token,
  Decimal,
  parseItem,
  parseList,
  parseDictionary,
  serializeItem,
  serializeList,
  serializeDictionary,
  serializeBareItem,
  type Item,
  type BareItem,
} from "../src/sfv.js";
import { MalformedSignatureError } from "../src/errors.js";

function item(value: BareItem, params: [string, BareItem][] = []): Item {
  return { value, params: new Map(params) };
}

describe("SFV parser: structural errors are rejected", () => {
  const cases: [string, () => unknown][] = [
    ["list missing comma between members", () => parseList("1 2")],
    ["list trailing comma", () => parseList("1, ")],
    ["dict missing comma between members", () => parseDictionary("a=1 b=2")],
    ["dict trailing comma", () => parseDictionary("a=1, ")],
    ["unterminated inner list", () => parseList("(")],
    ["inner list missing SP or )", () => parseList("(1,2)")],
    ["invalid key start (digit)", () => parseDictionary("9=1")],
    ["unexpected bare-item character", () => parseItem("@")],
    ["unterminated string", () => parseItem('"abc')],
    ["expected digit in number", () => parseItem("-")],
    ["integer too long", () => parseItem("1234567890123456")],
    ["decimal integer part too long", () => parseItem("1234567890123.5")],
    ["decimal missing fractional digits", () => parseItem("1.")],
    ["invalid boolean", () => parseItem("?2")],
    ["unterminated byte sequence", () => parseItem(":AQID")],
    ["non-canonical base64", () => parseItem(":AR==:")],
    ["invalid base64", () => parseItem(":!!!notbase64:")],
  ];
  for (const [name, fn] of cases) {
    test(`rejects: ${name}`, () => {
      assert.throws(fn, MalformedSignatureError);
    });
  }

  test("control character inside a string is rejected", () => {
    assert.throws(
      () => parseItem(`"a${String.fromCharCode(1)}b"`),
      MalformedSignatureError,
    );
  });
});

describe("SFV parser: accepted edge cases", () => {
  test("leading spaces before a list are skipped", () => {
    assert.equal(serializeList(parseList("  1, 2")), "1, 2");
  });

  test("negative integers and decimals", () => {
    assert.equal(parseItem("-5").value, -5);
    const dec = parseItem("-1.5");
    assert.ok(dec.value instanceof Decimal);
    assert.equal((dec.value as Decimal).value, -1.5);
  });

  test("tokens may contain ':' and '/'", () => {
    const t = parseItem("a:b/c");
    assert.ok(t.value instanceof Token);
    assert.equal((t.value as Token).value, "a:b/c");
  });

  test("'*' is a valid key start and token start", () => {
    const dict = parseDictionary("*=1");
    assert.deepEqual([...dict.keys()], ["*"]);
    assert.ok(parseItem("*foo").value instanceof Token);
  });

  test("parameters: bare flags and valued params round-trip", () => {
    assert.equal(serializeItem(parseItem("foo;a;b=2")), "foo;a;b=2");
  });

  test("inner list with list-level parameters round-trips", () => {
    assert.equal(serializeList(parseList('("x");q=9')), '("x");q=9');
  });

  test("dictionary boolean member with parameters round-trips", () => {
    assert.equal(serializeDictionary(parseDictionary("a;x=1")), "a;x=1");
  });

  test("dictionary inner-list member round-trips", () => {
    assert.equal(serializeDictionary(parseDictionary('a=("x" "y")')), 'a=("x" "y")');
  });

  test("empty input parses to an empty list and dictionary", () => {
    assert.deepEqual(parseList(""), []);
    assert.deepEqual([...parseDictionary("")], []);
  });
});

describe("SFV serializer: branches and errors", () => {
  test("integer serialization rejects non-integers", () => {
    assert.throws(() => serializeItem(item(1.5)), MalformedSignatureError);
  });

  test("decimal serialization rejects non-finite values", () => {
    assert.throws(() => serializeItem(item(new Decimal(Infinity))), MalformedSignatureError);
  });

  test("decimal with an integer value gains a '.0' fraction", () => {
    assert.equal(serializeItem(item(new Decimal(4))), "4.0");
  });

  test("string serialization rejects control characters", () => {
    assert.throws(
      () => serializeItem(item(`x${String.fromCharCode(1)}`)),
      MalformedSignatureError,
    );
  });

  test("unknown bare-item type is rejected", () => {
    assert.throws(() => serializeBareItem({} as unknown as BareItem), MalformedSignatureError);
  });

  test("byte sequence round-trips through canonical base64", () => {
    assert.equal(serializeItem(parseItem(":AQID/w==:")), ":AQID/w==:");
  });
});
