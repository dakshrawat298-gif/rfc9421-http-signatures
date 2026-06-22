/**
 * Signature base construction (RFC 9421 §2). Shared by the signer and verifier.
 *
 * Covers derived components (§2.2), HTTP field canonicalization (§2.1) including
 * the `sf` / `key` / `bs` / `req` parameters, and the trailing
 * `@signature-params` line (§2.3, §2.5). Output carries LF separators and NO
 * trailing newline.
 */

import { UnsupportedComponentError } from "./errors.js";
import {
  ByteSequence,
  parseDictionary,
  parseItem,
  parseList,
  serializeDictionary,
  serializeInnerList,
  serializeItem,
  serializeList,
  serializeParameters,
  type InnerList,
  type Item,
  type ListMember,
  type Parameters,
} from "./sfv.js";
import type {
  ComponentSpec,
  HttpMessage,
  RequestLike,
  ResponseLike,
  SignatureParameters,
} from "./types.js";

const te = new TextEncoder();

function trimOWS(value: string): string {
  return value.replace(/^[ \t]+/, "").replace(/[ \t]+$/, "");
}

/**
 * Re-encode a query parameter name/value for `@query-param` (RFC 9421 §2.2.8
 * step 2). The names/values are first parsed as application/x-www-form-urlencoded
 * (which `URLSearchParams` does on read — `+` and `%XX` are decoded), then
 * re-encoded. The normative §2.2.8 examples encode space as `%20` and newline as
 * `%0A` (e.g. `bar=with+plus+whitespace` -> `with%20plus%20whitespace`), i.e.
 * exactly `encodeURIComponent`. This deliberately differs from the WHATWG form
 * *serializer*, which emits `+` for space; the RFC examples use `%20`.
 */
function encodeQueryComponent(value: string): string {
  return encodeURIComponent(value);
}

/** Convert a public {@link ComponentSpec} into an SFV component-identifier Item. */
export function toComponentItem(spec: ComponentSpec): Item {
  if (typeof spec === "string") {
    return { value: spec.toLowerCase(), params: new Map() };
  }
  const params: Parameters = new Map();
  const p = spec.params ?? {};
  if (p.sf) params.set("sf", true);
  if (p.key !== undefined) params.set("key", p.key);
  if (p.bs) params.set("bs", true);
  if (p.req) params.set("req", true);
  if (p.tr) params.set("tr", true);
  if (p.name !== undefined) params.set("name", p.name);
  return { value: spec.name.toLowerCase(), params };
}

/** The canonical identifier string for a covered component (name + params). */
export function componentId(item: Item): string {
  return serializeItem(item);
}

/**
 * The bare covered-component identifier (unquoted name + params) used in
 * {@link VerifyResult.coveredComponents} and required-component matching.
 */
export function coveredComponentId(item: Item): string {
  return String(item.value) + serializeParameters(item.params);
}

function isResponse(message: HttpMessage): message is ResponseLike {
  return "status" in message;
}

function getSource(message: HttpMessage, item: Item): HttpMessage {
  if (item.params.has("req")) {
    const related = (message as ResponseLike).relatedRequest;
    if (!related) {
      throw new UnsupportedComponentError(
        `component "${String(item.value)}";req requires a related request`,
      );
    }
    return related;
  }
  return message;
}

function asRequest(source: HttpMessage, name: string): RequestLike {
  if (!("method" in source) || !("url" in source)) {
    throw new UnsupportedComponentError(`derived component ${name} requires a request context`);
  }
  return source;
}

function urlOf(req: RequestLike): URL {
  return new URL(req.url.toString());
}

function derivedValue(message: HttpMessage, item: Item, name: string): string {
  const source = getSource(message, item);

  if (name === "@status") {
    if (!isResponse(source)) {
      throw new UnsupportedComponentError("@status is only valid on a response");
    }
    return String(source.status);
  }

  const req = asRequest(source, name);
  const url = urlOf(req);

  switch (name) {
    case "@method":
      return req.method.toUpperCase();
    case "@target-uri":
      return url.href;
    case "@authority":
      return url.host.toLowerCase();
    case "@scheme":
      return url.protocol.replace(/:$/, "").toLowerCase();
    case "@request-target":
      return url.pathname + url.search;
    case "@path":
      return url.pathname;
    case "@query":
      return url.search === "" ? "?" : url.search;
    case "@query-param": {
      const pname = item.params.get("name");
      if (typeof pname !== "string") {
        throw new UnsupportedComponentError("@query-param requires a name parameter");
      }
      // RFC 9421 §2.2.8: the `name` identifier and the component value are both
      // the *re-encoded* strings. URLSearchParams iteration yields the decoded
      // name/value (form parsing, step 1); encodeQueryComponent re-encodes
      // (step 2). Match on the re-encoded name, emit the re-encoded value.
      let value: string | undefined;
      for (const [n, v] of url.searchParams) {
        if (encodeQueryComponent(n) === pname) {
          value = encodeQueryComponent(v);
          break;
        }
      }
      if (value === undefined) {
        throw new UnsupportedComponentError(`@query-param;name="${pname}" is not present`);
      }
      return value;
    }
    default:
      throw new UnsupportedComponentError(`unsupported derived component ${name}`);
  }
}

function serializeListMember(member: ListMember): string {
  return "items" in member ? serializeInnerList(member) : serializeItem(member);
}

function reserializeStructured(value: string): string {
  try {
    return serializeDictionary(parseDictionary(value));
  } catch {
    /* not a dictionary */
  }
  try {
    return serializeList(parseList(value));
  } catch {
    /* not a list */
  }
  return serializeItem(parseItem(value));
}

function fieldValue(message: HttpMessage, item: Item, name: string): string {
  const source = getSource(message, item);
  // RFC 9421 §2.1.1: `;tr` covers a field carried in the trailer section, which
  // is a map distinct from the header section.
  const isTrailer = item.params.has("tr");
  const fields = isTrailer ? source.trailers ?? {} : source.headers;
  const raw = fields[name];
  if (raw === undefined) {
    throw new UnsupportedComponentError(
      `covered ${isTrailer ? "trailer" : "field"} "${name}" is not present`,
    );
  }
  const values = (Array.isArray(raw) ? raw : [raw]).map(trimOWS);

  if (item.params.has("bs")) {
    return values.map((v) => serializeItem({ value: new ByteSequence(te.encode(v)), params: new Map() })).join(", ");
  }

  if (item.params.has("sf")) {
    return reserializeStructured(values.join(", "));
  }

  const key = item.params.get("key");
  if (key !== undefined) {
    if (typeof key !== "string") {
      throw new UnsupportedComponentError("key parameter must be a string");
    }
    const dict = parseDictionary(values.join(", "));
    const member = dict.get(key);
    if (!member) {
      throw new UnsupportedComponentError(`dictionary key "${key}" is not present in ${name}`);
    }
    return serializeListMember(member);
  }

  return values.join(", ");
}

function componentValue(message: HttpMessage, item: Item): string {
  if (typeof item.value !== "string") {
    throw new UnsupportedComponentError("component identifier must be a string");
  }
  const name = item.value;
  return name.startsWith("@") ? derivedValue(message, item, name) : fieldValue(message, item, name);
}

/** Build the signature base from resolved component Items and the params line. */
export function buildSignatureBase(
  message: HttpMessage,
  items: Item[],
  signatureParamsLine: string,
): string {
  const lines = items.map((item) => `${componentId(item)}: ${componentValue(message, item)}`);
  lines.push(`"@signature-params": ${signatureParamsLine}`);
  return lines.join("\n");
}

/** Map {@link SignatureParameters} into an ordered SFV parameter Map. */
export function signatureParamsToMap(params: SignatureParameters): Parameters {
  const map: Parameters = new Map();
  if (params.created !== undefined && params.created !== null) map.set("created", params.created);
  if (params.expires !== undefined && params.expires !== null) map.set("expires", params.expires);
  if (params.keyid !== undefined) map.set("keyid", params.keyid);
  if (params.alg !== undefined) map.set("alg", params.alg);
  if (params.nonce !== undefined) map.set("nonce", params.nonce);
  if (params.tag !== undefined) map.set("tag", params.tag);
  return map;
}

/** Serialize the `@signature-params` inner-list value (Signature-Input value). */
export function serializeSignatureParams(items: Item[], params: SignatureParameters): string {
  const inner: InnerList = { items, params: signatureParamsToMap(params) };
  return serializeInnerList(inner);
}

/**
 * Build the RFC 9421 signature base byte string (§2.5) for the given message,
 * covered components, and signature parameters.
 */
export function createSignatureBase(
  message: HttpMessage,
  components: ComponentSpec[],
  params: SignatureParameters,
): string {
  const items = components.map(toComponentItem);
  const line = serializeSignatureParams(items, params);
  return buildSignatureBase(message, items, line);
}

/** Reconstruct the signature base for verification from a parsed inner list. */
export function buildSignatureBaseFromInnerList(
  message: HttpMessage,
  inner: InnerList,
): string {
  return buildSignatureBase(message, inner.items, serializeInnerList(inner));
}
