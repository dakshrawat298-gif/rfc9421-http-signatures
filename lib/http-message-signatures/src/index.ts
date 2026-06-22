/**
 * @interledger-aligned/http-message-signatures
 *
 * Strict, zero-dependency RFC 9421 (HTTP Message Signatures) implementation.
 * Curated public surface (TSD §4.1). Subpaths `/sfv`, `/sign`, `/verify` expose
 * the layers individually for tree-shaking.
 */

export * from "./errors.js";
export * from "./types.js";
export { createSignatureBase, signMessage } from "./sign.js";
export { verifyMessage } from "./verify.js";

export {
  Token,
  ByteSequence,
  Decimal,
  parseItem,
  parseList,
  parseDictionary,
  serializeBareItem,
  serializeItem,
  serializeList,
  serializeDictionary,
} from "./sfv.js";

export type {
  BareItem,
  Parameters,
  Item,
  InnerList,
  ListMember,
  List,
  Dictionary,
} from "./sfv.js";
