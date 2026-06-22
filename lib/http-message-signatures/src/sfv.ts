/**
 * Structured Field Values codec (RFC 8941) — public subpath `/sfv`.
 *
 * RFC 9421 is built on RFC 8941 serialization (component identifiers,
 * `@signature-params`, and the `Signature` / `Signature-Input` Dictionaries).
 *
 * Amendment A1: Token and String are distinct tagged types and are never
 * coerced into one another, on either parse or serialize.
 */

import { MalformedSignatureError } from "./errors.js";

/** RFC 8941 §3.3.4 Token (bare, e.g. `foo`, `*`, derived component names). */
export class Token {
  public readonly value: string;
  public constructor(value: string) {
    this.value = value;
  }
}

/** RFC 8941 §3.3.5 Byte Sequence (`:base64:`). */
export class ByteSequence {
  public readonly bytes: Uint8Array;
  public constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }
}

/** RFC 8941 §3.3.2 Decimal — kept distinct from Integer (a value with `.`). */
export class Decimal {
  public readonly value: number;
  public constructor(value: number) {
    this.value = value;
  }
}

/**
 * A bare item. String is a plain JS `string`; Integer is a plain JS `number`;
 * Boolean is a plain JS `boolean`. Token, Decimal and Byte Sequence are tagged.
 */
export type BareItem = number | boolean | string | Token | Decimal | ByteSequence;

/** Ordered parameters attached to an item or inner list (RFC 8941 §3.1.2). */
export type Parameters = Map<string, BareItem>;

/** An Item: a bare value with parameters (RFC 8941 §3.3). */
export interface Item {
  value: BareItem;
  params: Parameters;
}

/** An Inner List: ordered items with list-level parameters (RFC 8941 §3.1.1). */
export interface InnerList {
  items: Item[];
  params: Parameters;
}

/** A member of a List or Dictionary value. */
export type ListMember = Item | InnerList;

/** A List (RFC 8941 §3.1). */
export type List = ListMember[];

/** A Dictionary (RFC 8941 §3.2); insertion order is significant. */
export type Dictionary = Map<string, ListMember>;

// ---------------------------------------------------------------------------
// Parsing (RFC 8941 §4.2)
// ---------------------------------------------------------------------------

function fail(message: string): never {
  throw new MalformedSignatureError(message);
}

function isDigit(c: string): boolean {
  return c >= "0" && c <= "9";
}

function isAlpha(c: string): boolean {
  return (c >= "a" && c <= "z") || (c >= "A" && c <= "Z");
}

function isLcAlpha(c: string): boolean {
  return c >= "a" && c <= "z";
}

/** tchar per RFC 7230 / RFC 8941 token continuation. */
const TCHAR = new Set("!#$%&'*+-.^_`|~");
function isTokenChar(c: string): boolean {
  return isAlpha(c) || isDigit(c) || TCHAR.has(c) || c === ":" || c === "/";
}

function isKeyChar(c: string): boolean {
  return isLcAlpha(c) || isDigit(c) || c === "_" || c === "-" || c === "." || c === "*";
}

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

class Parser {
  private readonly s: string;
  private i = 0;

  public constructor(input: string) {
    this.s = input;
  }

  private peek(): string {
    return this.i < this.s.length ? this.s[this.i]! : "";
  }

  private next(): string {
    return this.i < this.s.length ? this.s[this.i++]! : "";
  }

  private eof(): boolean {
    return this.i >= this.s.length;
  }

  private skipSP(): void {
    while (this.peek() === " ") this.i += 1;
  }

  private skipOWS(): void {
    while (this.peek() === " " || this.peek() === "\t") this.i += 1;
  }

  public parseItemTopLevel(): Item {
    this.skipSP();
    const item = this.parseItem();
    this.skipSP();
    if (!this.eof()) fail("trailing characters after item");
    return item;
  }

  public parseListTopLevel(): List {
    this.skipSP();
    // parseList consumes through EOF or throws, so no trailing check is needed.
    return this.parseList();
  }

  public parseDictionaryTopLevel(): Dictionary {
    this.skipSP();
    // parseDictionary consumes through EOF or throws, so no trailing check.
    return this.parseDictionary();
  }

  private parseList(): List {
    const members: List = [];
    while (!this.eof()) {
      members.push(this.parseListMember());
      this.skipOWS();
      if (this.eof()) break;
      if (this.next() !== ",") fail("expected comma between list members");
      this.skipOWS();
      if (this.eof()) fail("trailing comma in list");
    }
    return members;
  }

  private parseListMember(): ListMember {
    if (this.peek() === "(") return this.parseInnerList();
    return this.parseItem();
  }

  private parseDictionary(): Dictionary {
    const dict: Dictionary = new Map();
    while (!this.eof()) {
      const key = this.parseKey();
      let member: ListMember;
      if (this.peek() === "=") {
        this.i += 1;
        member = this.parseListMember();
      } else {
        member = { value: true, params: this.parseParameters() };
      }
      // Strict parsing: a repeated key is ambiguous in a security-sensitive
      // context, so reject rather than silently letting the last value win.
      if (dict.has(key)) fail(`duplicate dictionary key: ${key}`);
      dict.set(key, member);
      this.skipOWS();
      if (this.eof()) break;
      if (this.next() !== ",") fail("expected comma between dictionary members");
      this.skipOWS();
      if (this.eof()) fail("trailing comma in dictionary");
    }
    return dict;
  }

  private parseInnerList(): InnerList {
    this.next(); // consume "(" (caller guarantees it via parseListMember)
    const items: Item[] = [];
    while (!this.eof()) {
      this.skipSP();
      if (this.peek() === ")") {
        this.i += 1;
        return { items, params: this.parseParameters() };
      }
      items.push(this.parseItem());
      if (this.peek() !== " " && this.peek() !== ")") fail("expected SP or ) in inner list");
    }
    return fail("unterminated inner list");
  }

  private parseItem(): Item {
    const value = this.parseBareItem();
    const params = this.parseParameters();
    return { value, params };
  }

  private parseParameters(): Parameters {
    const params: Parameters = new Map();
    while (this.peek() === ";") {
      this.i += 1;
      this.skipSP();
      const key = this.parseKey();
      let value: BareItem = true;
      if (this.peek() === "=") {
        this.i += 1;
        value = this.parseBareItem();
      }
      if (params.has(key)) fail(`duplicate parameter key: ${key}`);
      params.set(key, value);
    }
    return params;
  }

  private parseKey(): string {
    const c = this.peek();
    if (!isLcAlpha(c) && c !== "*") fail("invalid key start");
    let out = "";
    while (!this.eof() && isKeyChar(this.peek())) out += this.next();
    return out;
  }

  private parseBareItem(): BareItem {
    const c = this.peek();
    if (c === '"') return this.parseString();
    if (c === ":") return this.parseByteSequence();
    if (c === "?") return this.parseBoolean();
    if (c === "-" || isDigit(c)) return this.parseNumber();
    if (isAlpha(c) || c === "*") return this.parseToken();
    return fail(`unexpected character '${c}' parsing bare item`);
  }

  private parseString(): string {
    this.next(); // consume opening quote (caller guarantees it via parseBareItem)
    let out = "";
    while (!this.eof()) {
      const ch = this.next();
      if (ch === "\\") {
        const esc = this.next();
        if (esc !== '"' && esc !== "\\") fail("invalid string escape");
        out += esc;
      } else if (ch === '"') {
        return out;
      } else {
        const code = ch.charCodeAt(0);
        if (code < 0x20 || code > 0x7e) fail("invalid string character");
        out += ch;
      }
    }
    return fail("unterminated string");
  }

  private parseToken(): Token {
    let out = this.next(); // already validated ALPHA / "*"
    while (!this.eof() && isTokenChar(this.peek())) out += this.next();
    return new Token(out);
  }

  private parseNumber(): number | Decimal {
    let sign = 1;
    if (this.peek() === "-") {
      this.i += 1;
      sign = -1;
    }
    if (!isDigit(this.peek())) fail("expected digit in number");
    let intPart = "";
    while (!this.eof() && isDigit(this.peek())) intPart += this.next();
    if (this.peek() !== ".") {
      if (intPart.length > 15) fail("integer too long");
      return sign * Number(intPart);
    }
    // Decimal
    if (intPart.length > 12) fail("decimal integer part too long");
    this.i += 1; // consume "."
    let fracPart = "";
    while (!this.eof() && isDigit(this.peek())) fracPart += this.next();
    if (fracPart.length === 0) fail("decimal missing fractional digits");
    if (fracPart.length > 3) fail("decimal has more than three fractional digits");
    return new Decimal(sign * Number(`${intPart}.${fracPart}`));
  }

  private parseBoolean(): boolean {
    this.next(); // consume "?" (caller guarantees it via parseBareItem)
    const c = this.next();
    if (c === "1") return true;
    if (c === "0") return false;
    return fail("invalid boolean");
  }

  private parseByteSequence(): ByteSequence {
    this.next(); // consume ":" (caller guarantees it via parseBareItem)
    let b64 = "";
    while (!this.eof() && this.peek() !== ":") b64 += this.next();
    if (this.next() !== ":") fail("unterminated byte sequence");
    if (!BASE64_RE.test(b64)) fail("invalid base64 in byte sequence");
    const bytes = new Uint8Array(Buffer.from(b64, "base64"));
    // Round-trip guard: reject input that does not re-encode to itself.
    if (Buffer.from(bytes).toString("base64") !== normalizeB64(b64)) {
      fail("non-canonical base64 in byte sequence");
    }
    return new ByteSequence(bytes);
  }
}

function normalizeB64(b64: string): string {
  // Re-pad so comparison against Buffer's canonical output is fair.
  const stripped = b64.replace(/=+$/, "");
  const pad = stripped.length % 4 === 0 ? "" : "=".repeat(4 - (stripped.length % 4));
  return stripped + pad;
}

/** Parse a Structured Field Item (RFC 8941 §4.2.3). */
export function parseItem(input: string): Item {
  return new Parser(input).parseItemTopLevel();
}

/** Parse a Structured Field List (RFC 8941 §4.2.1). */
export function parseList(input: string): List {
  return new Parser(input).parseListTopLevel();
}

/** Parse a Structured Field Dictionary (RFC 8941 §4.2.2). */
export function parseDictionary(input: string): Dictionary {
  return new Parser(input).parseDictionaryTopLevel();
}

// ---------------------------------------------------------------------------
// Serialization (RFC 8941 §4.1)
// ---------------------------------------------------------------------------

function serializeDecimal(value: number): string {
  if (!Number.isFinite(value)) fail("cannot serialize non-finite decimal");
  // RFC 8941 §3.3.2 data model: at most 12 integer digits.
  if (Math.abs(value) >= 1e12) fail("decimal integer part exceeds the 12-digit limit");
  // Strict serialization: reject values that cannot be represented exactly with
  // at most three fractional digits rather than silently rounding, which would
  // alter the signed canonical bytes.
  const scaled = value * 1000;
  if (Math.abs(scaled - Math.round(scaled)) > 1e-9) {
    fail("decimal exceeds the three fractional-digit limit");
  }
  let out = (Math.round(scaled) / 1000).toString();
  if (!out.includes(".")) out += ".0";
  return out;
}

/** Validate and serialize a Token (RFC 8941 §4.1.9): ALPHA/"*" start, tchar/":"/"/" rest. */
function serializeToken(value: string): string {
  const first = value[0];
  if (first === undefined || (!isAlpha(first) && first !== "*")) {
    fail("token must start with an ALPHA character or '*'");
  }
  for (const c of value) {
    if (!isTokenChar(c)) fail(`invalid token character: ${JSON.stringify(c)}`);
  }
  return value;
}

/** Serialize a bare item (RFC 8941 §4.1.3). */
export function serializeBareItem(value: BareItem): string {
  if (typeof value === "boolean") return value ? "?1" : "?0";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) fail("Integer value must be an integer");
    return String(value);
  }
  if (typeof value === "string") {
    let out = '"';
    for (const ch of value) {
      const code = ch.charCodeAt(0);
      if (code < 0x20 || code > 0x7e) fail("invalid character in string");
      if (ch === "\\" || ch === '"') out += "\\";
      out += ch;
    }
    return out + '"';
  }
  if (value instanceof Token) return serializeToken(value.value);
  if (value instanceof Decimal) return serializeDecimal(value.value);
  if (value instanceof ByteSequence) {
    return `:${Buffer.from(value.bytes).toString("base64")}:`;
  }
  return fail("unknown bare item type");
}

function serializeParameters(params: Parameters): string {
  let out = "";
  for (const [key, value] of params) {
    out += ";" + key;
    if (value !== true) out += "=" + serializeBareItem(value);
  }
  return out;
}

/** Serialize an Item (RFC 8941 §4.1.3). */
export function serializeItem(item: Item): string {
  return serializeBareItem(item.value) + serializeParameters(item.params);
}

function isInnerList(member: ListMember): member is InnerList {
  return "items" in member;
}

function serializeInnerList(list: InnerList): string {
  return "(" + list.items.map(serializeItem).join(" ") + ")" + serializeParameters(list.params);
}

function serializeMember(member: ListMember): string {
  return isInnerList(member) ? serializeInnerList(member) : serializeItem(member);
}

/** Serialize a List (RFC 8941 §4.1.1). */
export function serializeList(list: List): string {
  return list.map(serializeMember).join(", ");
}

/** Serialize a Dictionary (RFC 8941 §4.1.2). */
export function serializeDictionary(dict: Dictionary): string {
  const parts: string[] = [];
  for (const [key, member] of dict) {
    if (!isInnerList(member) && member.value === true) {
      parts.push(key + serializeParameters(member.params));
    } else {
      parts.push(key + "=" + serializeMember(member));
    }
  }
  return parts.join(", ");
}

/** Internal: serialize an InnerList (used by the signature-base layer). */
export { serializeInnerList };

/** Internal: serialize an SFV parameter map (used by the signature-base layer). */
export { serializeParameters };
