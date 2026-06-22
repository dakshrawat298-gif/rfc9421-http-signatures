/**
 * Structured Field Values codec (RFC 8941) — public subpath `/sfv`.
 *
 * RFC 9421 is built on RFC 8941 serialization (component identifiers,
 * `@signature-params`, and the `Signature` / `Signature-Input` Dictionaries).
 *
 * Amendment A1: Token and String are distinct tagged types and are never
 * coerced into one another, on either parse or serialize.
 *
 * NOTE: scaffold only — parsing/serialization is implemented in Layer 0 (Step 3).
 */

import { NotImplementedError } from "./errors.js";

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

/** Parse a Structured Field Item (RFC 8941 §4.2.3). */
export function parseItem(_input: string): Item {
  throw new NotImplementedError("sfv.parseItem");
}

/** Parse a Structured Field List (RFC 8941 §4.2.1). */
export function parseList(_input: string): List {
  throw new NotImplementedError("sfv.parseList");
}

/** Parse a Structured Field Dictionary (RFC 8941 §4.2.2). */
export function parseDictionary(_input: string): Dictionary {
  throw new NotImplementedError("sfv.parseDictionary");
}

/** Serialize a bare item (RFC 8941 §4.1.3). */
export function serializeBareItem(_value: BareItem): string {
  throw new NotImplementedError("sfv.serializeBareItem");
}

/** Serialize an Item (RFC 8941 §4.1.3). */
export function serializeItem(_item: Item): string {
  throw new NotImplementedError("sfv.serializeItem");
}

/** Serialize a List (RFC 8941 §4.1.1). */
export function serializeList(_list: List): string {
  throw new NotImplementedError("sfv.serializeList");
}

/** Serialize a Dictionary (RFC 8941 §4.1.2). */
export function serializeDictionary(_dict: Dictionary): string {
  throw new NotImplementedError("sfv.serializeDictionary");
}
