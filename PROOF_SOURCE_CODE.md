# PROOF_SOURCE_CODE — Verbatim Source Evidence

> Master evidence file compiled for secondary AI (NotebookLM) security audit of
> `@interledger-aligned/http-message-signatures` (RFC 9421).
> Every block below is a 100% verbatim, unedited copy of the named production file.
> Generated: 2026-06-23 17:13:14 UTC

| # | File | Lines |
| - | ---- | ----- |
| 1 | src/crypto.ts | 75 |
| 2 | src/sign.ts | 88 |
| 3 | src/verify.ts | 365 |
| 4 | src/sfv.ts | 444 |
| 5 | src/base.ts | 277 |
| 6 | src/errors.ts | 102 |
| 7 | package.json | 88 |
| 8 | test/fixtures/rfc9421-vectors.ts | 362 |

---

### File: src/crypto.ts

```typescript
/**
 * Internal: maps registered RFC 9421 algorithm identifiers (§6.2.2) to the
 * WebCrypto parameters used when signing/verifying with a raw `CryptoKey`.
 */

import { UnsupportedAlgorithmError } from "./errors.js";
import type { SignatureAlgorithm } from "./types.js";

let cachedSubtle: SubtleCrypto | undefined;

/**
 * Resolve the runtime WebCrypto {@link SubtleCrypto}, preferring the standard
 * `globalThis.crypto.subtle` (browsers, Deno, edge runtimes, Node 19+). On
 * Node 18 — where the global is not exposed by default — fall back to the
 * `node:crypto` WebCrypto instance via a gated dynamic import. The legacy
 * `node:crypto` `sign()`/`verify()` APIs are never used.
 */
export async function getSubtle(): Promise<SubtleCrypto> {
  if (cachedSubtle) return cachedSubtle;
  const globalSubtle = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;
  if (globalSubtle) {
    cachedSubtle = globalSubtle;
    return cachedSubtle;
  }
  const nodeSubtle = (await import("node:crypto")).webcrypto?.subtle as SubtleCrypto | undefined;
  if (nodeSubtle) {
    cachedSubtle = nodeSubtle;
    return cachedSubtle;
  }
  throw new UnsupportedAlgorithmError(
    "WebCrypto is unavailable: this runtime exposes no globalThis.crypto.subtle",
  );
}

/** The registered, supported algorithm identifiers. */
export const SUPPORTED_ALGORITHMS: readonly SignatureAlgorithm[] = [
  "rsa-pss-sha512",
  "rsa-v1_5-sha256",
  "ecdsa-p256-sha256",
  "ecdsa-p384-sha384",
  "ed25519",
  "hmac-sha256",
];

/** Narrow an arbitrary string to a supported {@link SignatureAlgorithm}. */
export function isSupportedAlgorithm(alg: string): alg is SignatureAlgorithm {
  return (SUPPORTED_ALGORITHMS as readonly string[]).includes(alg);
}

type SignAlg =
  | { name: "RSASSA-PKCS1-v1_5" }
  | { name: "RSA-PSS"; saltLength: number }
  | { name: "ECDSA"; hash: "SHA-256" | "SHA-384" }
  | { name: "Ed25519" }
  | { name: "HMAC" };

/** WebCrypto sign/verify parameters for a registered algorithm. */
export function webcryptoSignParams(alg: SignatureAlgorithm): SignAlg {
  switch (alg) {
    case "rsa-pss-sha512":
      return { name: "RSA-PSS", saltLength: 64 };
    case "rsa-v1_5-sha256":
      return { name: "RSASSA-PKCS1-v1_5" };
    case "ecdsa-p256-sha256":
      return { name: "ECDSA", hash: "SHA-256" };
    case "ecdsa-p384-sha384":
      return { name: "ECDSA", hash: "SHA-384" };
    case "ed25519":
      return { name: "Ed25519" };
    case "hmac-sha256":
      return { name: "HMAC" };
    default:
      throw new UnsupportedAlgorithmError(`unsupported algorithm: ${String(alg)}`);
  }
}
```

---

### File: src/sign.ts

```typescript
/**
 * Public signer — subpath `/sign` (RFC 9421 §3.1, §4.1–4.2).
 */

import { UnsupportedAlgorithmError } from "./errors.js";
import { buildSignatureBase, serializeSignatureParams, toComponentItem } from "./base.js";
import { ByteSequence, serializeItem } from "./sfv.js";
import { getSubtle, webcryptoSignParams } from "./crypto.js";
import type {
  ComponentSpec,
  CryptoKey,
  HttpMessage,
  SignOptions,
  SignResult,
  SignatureAlgorithm,
  SignatureParameters,
  SigningKey,
} from "./types.js";

export { createSignatureBase } from "./base.js";

const te = new TextEncoder();

function isSigningKey(key: SigningKey | CryptoKey): key is SigningKey {
  return typeof (key as Partial<SigningKey>).sign === "function" && "alg" in key;
}

async function rawSign(
  key: CryptoKey,
  alg: SignatureAlgorithm,
  data: Uint8Array,
): Promise<Uint8Array> {
  const input = new Uint8Array(data.byteLength);
  input.set(data);
  const subtle = await getSubtle();
  const sig = await subtle.sign(webcryptoSignParams(alg), key, input);
  return new Uint8Array(sig);
}

/**
 * Sign an HTTP message, returning the `Signature-Input` / `Signature` header
 * values (RFC 9421 §3.1).
 */
export async function signMessage(
  message: HttpMessage,
  options: SignOptions,
): Promise<SignResult> {
  const components: ComponentSpec[] = options.components;
  const label = options.label ?? "sig";

  let signFn: (data: Uint8Array) => Promise<Uint8Array> | Uint8Array;
  let keyKeyid: string | undefined;

  if (isSigningKey(options.key)) {
    const signer = options.key;
    keyKeyid = signer.keyid;
    signFn = (data) => signer.sign(data);
  } else {
    if (options.alg === undefined) {
      throw new UnsupportedAlgorithmError(
        "signing with a raw CryptoKey requires an explicit `alg` (no insecure default)",
      );
    }
    const cryptoKey = options.key;
    const chosen = options.alg;
    signFn = (data) => rawSign(cryptoKey, chosen, data);
  }

  // Assemble the effective signature parameters (no algorithm is injected
  // automatically; it is emitted only when the caller sets it explicitly).
  const params: SignatureParameters = { ...(options.params ?? {}) };
  if (params.keyid === undefined) {
    const keyid = options.keyid ?? keyKeyid;
    if (keyid !== undefined) params.keyid = keyid;
  }

  const items = components.map(toComponentItem);
  const signatureParamsLine = serializeSignatureParams(items, params);
  const base = buildSignatureBase(message, items, signatureParamsLine);

  const signatureBytes = await signFn(te.encode(base));
  const sigItem = serializeItem({ value: new ByteSequence(signatureBytes), params: new Map() });

  return {
    signatureInput: `${label}=${signatureParamsLine}`,
    signature: `${label}=${sigItem}`,
  };
}
```

---

### File: src/verify.ts

```typescript
/**
 * Public verifier — subpath `/verify` (RFC 9421 §3.2, §4.1–4.3).
 *
 * Returns a structured result; it never throws on a merely-invalid signature.
 * It throws only when the input is malformed (TSD §3.1 boundary): missing
 * Signature-Input, non-byte-sequence Signature, or an unsupported `alg` token.
 */

import {
  MalformedSignatureError,
  UnsupportedAlgorithmError,
} from "./errors.js";
import {
  buildSignatureBaseFromInnerList,
  coveredComponentId,
  toComponentItem,
} from "./base.js";
import { getSubtle, isSupportedAlgorithm, webcryptoSignParams } from "./crypto.js";
import {
  ByteSequence,
  parseDictionary,
  type Dictionary,
  type InnerList,
  type ListMember,
} from "./sfv.js";
import type {
  CryptoKey,
  HttpMessage,
  SignatureAlgorithm,
  VerifierPolicy,
  VerifyingKey,
  VerifyOptions,
  VerifyResult,
} from "./types.js";

const te = new TextEncoder();

/**
 * Build a {@link VerifyingKey} from a raw WebCrypto {@link CryptoKey} bound to a
 * single registered algorithm. The verification primitive — key usage, the
 * per-algorithm WebCrypto parameters, and the IEEE P1363 `r||s` signature
 * encoding that WebCrypto requires for ECDSA (RFC 9421 §3.3.4) — is owned by the
 * library, mirroring the raw-key signing path in {@link signMessage}. A
 * CryptoKey corresponds to exactly one registered algorithm, so the permitted
 * set is `[alg]`, which preserves the §3.2 algorithm-downgrade defense.
 */
export function createVerifyingKey(key: CryptoKey, alg: SignatureAlgorithm): VerifyingKey {
  if (!isSupportedAlgorithm(alg)) {
    throw new UnsupportedAlgorithmError(`unsupported algorithm: ${String(alg)}`);
  }
  const params = webcryptoSignParams(alg);
  return {
    algs: [alg],
    async verify(data: Uint8Array, signature: Uint8Array): Promise<boolean> {
      const d = new Uint8Array(data.byteLength);
      d.set(data);
      const s = new Uint8Array(signature.byteLength);
      s.set(signature);
      const subtle = await getSubtle();
      return subtle.verify(params, key, s, d);
    },
  };
}

function headerValue(headers: HttpMessage["headers"], name: string): string | undefined {
  const raw = headers[name];
  if (raw === undefined) return undefined;
  return Array.isArray(raw) ? raw.join(", ") : raw;
}

function isInnerList(member: ListMember): member is InnerList {
  return "items" in member;
}

/**
 * RFC 9421 §2.3: `alg`, `keyid`, `nonce`, and `tag` are String values. A
 * parameter that is present but carries any other Structured Field type (Token,
 * Integer, Boolean, Byte Sequence, …) is malformed — silently ignoring it would
 * open an algorithm-confusion downgrade (e.g. `alg` smuggled as a bare Token so
 * the allow-list never sees it).
 */
function strictString(params: InnerList["params"], key: string): string | undefined {
  if (!params.has(key)) return undefined;
  const v = params.get(key);
  if (typeof v !== "string") {
    throw new MalformedSignatureError(`@signature-params "${key}" must be a String`);
  }
  return v;
}

/**
 * RFC 9421 §2.3: `created` and `expires` are Integer values. A Decimal or any
 * non-integer is malformed; accepting it as "absent" would silently bypass the
 * freshness/expiry checks.
 */
function strictInteger(params: InnerList["params"], key: string): number | undefined {
  if (!params.has(key)) return undefined;
  const v = params.get(key);
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new MalformedSignatureError(`@signature-params "${key}" must be an Integer`);
  }
  return v;
}

interface ParsedSignature {
  label: string;
  inner: InnerList;
  signatureBytes: Uint8Array;
  created: number | undefined;
  expires: number | undefined;
  keyid: string | undefined;
  alg: SignatureAlgorithm | undefined;
  nonce: string | undefined;
  tag: string | undefined;
  coveredComponents: string[];
}

function parseSignatures(message: HttpMessage): ParsedSignature[] {
  const inputRaw = headerValue(message.headers, "signature-input");
  const sigRaw = headerValue(message.headers, "signature");

  if (sigRaw !== undefined && inputRaw === undefined) {
    throw new MalformedSignatureError("Signature present without a matching Signature-Input");
  }
  if (inputRaw === undefined) {
    throw new MalformedSignatureError("no Signature-Input field is present");
  }
  if (sigRaw === undefined) {
    throw new MalformedSignatureError("Signature-Input present without a matching Signature");
  }

  let inputDict: Dictionary;
  let sigDict: Dictionary;
  try {
    inputDict = parseDictionary(inputRaw);
    sigDict = parseDictionary(sigRaw);
  } catch (cause) {
    throw new MalformedSignatureError("unparseable Signature/Signature-Input field", { cause });
  }

  const parsed: ParsedSignature[] = [];
  for (const [label, member] of inputDict) {
    if (!isInnerList(member)) {
      throw new MalformedSignatureError(`Signature-Input "${label}" is not an inner list`);
    }
    const sigMember = sigDict.get(label);
    if (!sigMember) {
      throw new MalformedSignatureError(`no Signature value for label "${label}"`);
    }
    if (isInnerList(sigMember) || !(sigMember.value instanceof ByteSequence)) {
      throw new MalformedSignatureError(`Signature "${label}" is not a byte sequence`);
    }

    const algRaw = strictString(member.params, "alg");
    let alg: SignatureAlgorithm | undefined;
    if (algRaw !== undefined) {
      if (!isSupportedAlgorithm(algRaw)) {
        throw new UnsupportedAlgorithmError(`unsupported algorithm token: ${algRaw}`);
      }
      alg = algRaw;
    }

    parsed.push({
      label,
      inner: member,
      signatureBytes: sigMember.value.bytes,
      created: strictInteger(member.params, "created"),
      expires: strictInteger(member.params, "expires"),
      keyid: strictString(member.params, "keyid"),
      alg,
      nonce: strictString(member.params, "nonce"),
      tag: strictString(member.params, "tag"),
      coveredComponents: member.items.map(coveredComponentId),
    });
  }
  return parsed;
}

function resolveClockTolerance(value: number | undefined): number {
  if (value === undefined) return 5;
  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError(
      `policy.clockTolerance must be a finite, non-negative number of seconds (received ${String(value)})`,
    );
  }
  return value;
}

function checkPolicy(
  sig: ParsedSignature,
  policy: VerifierPolicy,
  now: number,
): string | undefined {
  const tolerance = resolveClockTolerance(policy.clockTolerance);

  if (policy.allowedAlgorithms) {
    // An allow-list cannot be enforced against a signature that declines to
    // state its algorithm, so refuse rather than silently waive the check.
    if (sig.alg === undefined) {
      return "policy restricts algorithms but the signature does not state one";
    }
    if (!policy.allowedAlgorithms.includes(sig.alg)) {
      return `algorithm ${sig.alg} is not allowed by policy`;
    }
  }

  if (policy.requiredCoveredComponents) {
    const covered = new Set(sig.coveredComponents);
    for (const spec of policy.requiredCoveredComponents) {
      const id = coveredComponentId(toComponentItem(spec));
      if (!covered.has(id)) {
        return `required covered component ${id} is missing`;
      }
    }
  }

  if (sig.created !== undefined && sig.created > now + tolerance) {
    return "signature created timestamp is in the future";
  }

  if (policy.maxAgeSeconds !== undefined) {
    if (sig.created === undefined) {
      return "policy enforces a maximum age but the signature has no created timestamp";
    }
    if (now - sig.created > policy.maxAgeSeconds + tolerance) {
      return "signature exceeds the maximum accepted age";
    }
  }

  if (sig.expires !== undefined && now > sig.expires + tolerance) {
    return "signature has expired";
  }

  if (policy.requireExpires && sig.expires === undefined) {
    return "policy requires an expires parameter";
  }

  if (policy.tag !== undefined && sig.tag !== policy.tag) {
    return "signature tag does not match policy";
  }

  return undefined;
}

async function verifyOne(
  message: HttpMessage,
  sig: ParsedSignature,
  options: VerifyOptions,
): Promise<VerifyResult> {
  const policy = options.policy ?? {};
  const now = options.now ? options.now() : Math.floor(Date.now() / 1000);

  const policyReason = checkPolicy(sig, policy, now);
  if (policyReason !== undefined) {
    return { valid: false, label: sig.label, reason: policyReason, coveredComponents: sig.coveredComponents };
  }

  // Replay defense (RFC 9421 §7.2.2): the application-supplied nonce hook is the
  // single-use gate. It is declared on the policy, so it MUST be honored.
  if (policy.nonceVerify) {
    let accepted: boolean;
    try {
      accepted = await policy.nonceVerify(sig.nonce);
    } catch (cause) {
      return {
        valid: false,
        label: sig.label,
        reason: `nonce verification errored: ${cause instanceof Error ? cause.message : String(cause)}`,
        coveredComponents: sig.coveredComponents,
      };
    }
    if (!accepted) {
      return {
        valid: false,
        label: sig.label,
        reason: "nonce rejected by policy (possible replay)",
        coveredComponents: sig.coveredComponents,
      };
    }
  }

  let key: VerifyingKey | null | undefined;
  try {
    key = await options.keyLookup(sig.keyid, sig.alg);
  } catch (cause) {
    return {
      valid: false,
      label: sig.label,
      reason: `key lookup failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      coveredComponents: sig.coveredComponents,
    };
  }
  if (!key) {
    return { valid: false, label: sig.label, reason: "no key resolved for signature", coveredComponents: sig.coveredComponents };
  }

  if (sig.alg !== undefined && !key.algs.includes(sig.alg)) {
    return {
      valid: false,
      label: sig.label,
      reason: `key does not permit algorithm ${sig.alg}`,
      coveredComponents: sig.coveredComponents,
    };
  }

  let base: string;
  try {
    base = buildSignatureBaseFromInnerList(message, sig.inner);
  } catch (cause) {
    return {
      valid: false,
      label: sig.label,
      reason: `cannot build signature base: ${cause instanceof Error ? cause.message : String(cause)}`,
      coveredComponents: sig.coveredComponents,
    };
  }

  let valid = false;
  try {
    valid = await key.verify(te.encode(base), sig.signatureBytes);
  } catch {
    valid = false;
  }

  return {
    valid,
    label: sig.label,
    coveredComponents: sig.coveredComponents,
    ...(valid ? {} : { reason: "signature verification failed" }),
  };
}

/**
 * Verify the signature(s) on an HTTP message against trusted key material
 * resolved through `options.keyLookup`, then apply verifier policy.
 */
export async function verifyMessage(
  message: HttpMessage,
  options: VerifyOptions,
): Promise<VerifyResult> {
  const all = parseSignatures(message);

  let targets: ParsedSignature[];
  if (options.label !== undefined) {
    const found = all.find((s) => s.label === options.label);
    if (!found) {
      throw new MalformedSignatureError(`no signature with label "${options.label}"`);
    }
    targets = [found];
  } else {
    targets = all;
  }

  if (targets.length === 0) {
    throw new MalformedSignatureError("no signatures to verify");
  }

  let lastValid: VerifyResult | undefined;
  for (const sig of targets) {
    const result = await verifyOne(message, sig, options);
    if (!result.valid) return result;
    lastValid = result;
  }
  return lastValid!;
}
```

---

### File: src/sfv.ts

```typescript
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
```

---

### File: src/base.ts

```typescript
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
```

---

### File: src/errors.ts

```typescript
/**
 * Typed error hierarchy for the HTTP Message Signatures library.
 *
 * RFC 9421 mapping:
 *  - §1.4 / §2.5  malformed input  -> MalformedMessageError / MalformedSignatureError
 *  - §3.3 / §6.2  algorithm registry -> UnsupportedAlgorithmError
 *  - §2.1 / §2.2  component identifiers -> UnsupportedComponentError
 *  - §3.2         key resolution      -> KeyResolutionError
 *  - §3.2 / §7.2  verifier policy      -> PolicyViolationError
 *  - §3.2         verification outcome -> VerificationFailedError
 *
 * Design rules (TSD §3.6):
 *  - Every error carries a stable, machine-readable `code`.
 *  - No error message includes secret material (keys, MAC bytes, signatures).
 */

/** Stable, programmatic error codes. */
export const ErrorCode = {
  Malformed: "ERR_MALFORMED_MESSAGE",
  MalformedSignature: "ERR_MALFORMED_SIGNATURE",
  UnsupportedAlgorithm: "ERR_UNSUPPORTED_ALGORITHM",
  UnsupportedComponent: "ERR_UNSUPPORTED_COMPONENT",
  KeyResolution: "ERR_KEY_RESOLUTION",
  PolicyViolation: "ERR_POLICY_VIOLATION",
  VerificationFailed: "ERR_VERIFICATION_FAILED",
  NotImplemented: "ERR_NOT_IMPLEMENTED",
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

/** Base class for every error thrown by this library. */
export class SignatureError extends Error {
  /** Stable, machine-readable code for programmatic handling. */
  public readonly code: ErrorCode;

  public constructor(message: string, code: ErrorCode, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
    this.code = code;
    // Preserve `instanceof` across down-level transpilation targets.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Input cannot be interpreted as a valid HTTP message component context. */
export class MalformedMessageError extends SignatureError {
  public constructor(message: string, options?: { cause?: unknown }) {
    super(message, ErrorCode.Malformed, options);
  }
}

/** The `Signature` / `Signature-Input` headers (or their SFV) are unparseable. */
export class MalformedSignatureError extends SignatureError {
  public constructor(message: string, options?: { cause?: unknown }) {
    super(message, ErrorCode.MalformedSignature, options);
  }
}

/** The requested signature algorithm is not in the supported registry. */
export class UnsupportedAlgorithmError extends SignatureError {
  public constructor(message: string, options?: { cause?: unknown }) {
    super(message, ErrorCode.UnsupportedAlgorithm, options);
  }
}

/** A covered component (derived or field) or its parameters are not supported. */
export class UnsupportedComponentError extends SignatureError {
  public constructor(message: string, options?: { cause?: unknown }) {
    super(message, ErrorCode.UnsupportedComponent, options);
  }
}

/** The verifier could not resolve trusted key material for the signature. */
export class KeyResolutionError extends SignatureError {
  public constructor(message: string, options?: { cause?: unknown }) {
    super(message, ErrorCode.KeyResolution, options);
  }
}

/** A well-formed signature violated verifier policy (expiry, required comps, alg allow-list). */
export class PolicyViolationError extends SignatureError {
  public constructor(message: string, options?: { cause?: unknown }) {
    super(message, ErrorCode.PolicyViolation, options);
  }
}

/** Cryptographic verification of a well-formed signature failed. */
export class VerificationFailedError extends SignatureError {
  public constructor(message: string, options?: { cause?: unknown }) {
    super(message, ErrorCode.VerificationFailed, options);
  }
}

/**
 * Internal scaffold error: thrown by not-yet-implemented stubs so the TDD suite
 * is red before core logic exists. Removed as each layer is implemented.
 */
export class NotImplementedError extends SignatureError {
  public constructor(what: string) {
    super(`Not implemented: ${what}`, ErrorCode.NotImplemented);
  }
}
```

---

### File: package.json

```json
{
  "name": "@interledger-aligned/http-message-signatures",
  "version": "0.1.0",
  "description": "Standalone, zero-dependency, dual ESM/CJS TypeScript implementation of RFC 9421 (HTTP Message Signatures) with strict compliance and no insecure defaults.",
  "keywords": [
    "rfc9421",
    "http-message-signatures",
    "http-signatures",
    "signature",
    "ed25519",
    "ecdsa",
    "rsa-pss",
    "hmac",
    "webcrypto",
    "interledger"
  ],
  "license": "Apache-2.0",
  "author": "Interledger-aligned contributors",
  "repository": {
    "type": "git",
    "url": "https://github.com/interledger-aligned/http-message-signatures.git"
  },
  "homepage": "https://github.com/interledger-aligned/http-message-signatures#readme",
  "bugs": {
    "url": "https://github.com/interledger-aligned/http-message-signatures/issues"
  },
  "type": "module",
  "sideEffects": false,
  "engines": {
    "node": ">=18"
  },
  "exports": {
    ".": {
      "workspace": "./src/index.ts",
      "types": "./dist/esm/index.d.ts",
      "import": "./dist/esm/index.js",
      "require": "./dist/cjs/index.js"
    },
    "./sfv": {
      "workspace": "./src/sfv.ts",
      "types": "./dist/esm/sfv.d.ts",
      "import": "./dist/esm/sfv.js",
      "require": "./dist/cjs/sfv.js"
    },
    "./sign": {
      "workspace": "./src/sign.ts",
      "types": "./dist/esm/sign.d.ts",
      "import": "./dist/esm/sign.js",
      "require": "./dist/cjs/sign.js"
    },
    "./verify": {
      "workspace": "./src/verify.ts",
      "types": "./dist/esm/verify.d.ts",
      "import": "./dist/esm/verify.js",
      "require": "./dist/cjs/verify.js"
    },
    "./package.json": "./package.json"
  },
  "main": "./dist/cjs/index.js",
  "module": "./dist/esm/index.js",
  "types": "./dist/esm/index.d.ts",
  "files": [
    "dist",
    "src",
    "LICENSE",
    "NOTICE",
    "README.md",
    "SECURITY.md"
  ],
  "scripts": {
    "build": "pnpm run build:esm && pnpm run build:cjs && pnpm run build:fixup",
    "build:esm": "tsc -p tsconfig.build.json",
    "build:cjs": "tsc -p tsconfig.cjs.json",
    "build:fixup": "node ./scripts/build-fixup.mjs",
    "clean": "rm -rf dist tsconfig.tsbuildinfo",
    "test": "node --import tsx --test \"test/**/*.test.ts\"",
    "test:coverage": "node --import tsx --test --experimental-test-coverage --test-coverage-exclude=\"src/types.ts\" --test-coverage-exclude=\"test/**\" \"test/**/*.test.ts\"",
    "test:coverage:check": "node --import tsx --test --experimental-test-coverage --test-coverage-exclude=\"src/types.ts\" --test-coverage-exclude=\"test/**\" --test-coverage-lines=95 --test-coverage-functions=95 --test-coverage-branches=90 \"test/**/*.test.ts\"",
    "typecheck": "tsc -p tsconfig.test.json",
    "validate:fixtures": "node --import tsx ./scripts/validate-fixtures.ts",
    "prepublishOnly": "pnpm run clean && pnpm run typecheck && pnpm run test:coverage:check && pnpm run validate:fixtures && pnpm run build"
  },
  "devDependencies": {
    "@types/node": "catalog:",
    "tsx": "catalog:",
    "typescript": "~5.9.3"
  }
}
```

---

### File: test/fixtures/rfc9421-vectors.ts

```typescript
/**
 * RFC 9421 Appendix B test vectors, transcribed verbatim from the authoritative
 * text at https://www.rfc-editor.org/rfc/rfc9421.txt.
 *
 * All RFC 8792 `\`-line-wrapping has been removed so every value below is the
 * exact, contiguous byte string the RFC defines. Signature bases preserve LF
 * separators between lines and carry NO trailing newline (RFC 9421 §2.5).
 *
 * Integrity of every value here is independently checked by
 * `scripts/validate-fixtures.ts`, which uses the platform WebCrypto (NOT this
 * library) to verify each published signature against its base and key.
 */

import type { SignatureAlgorithm } from "../../src/types.js";

// ---------------------------------------------------------------------------
// B.1 Keys
// ---------------------------------------------------------------------------

/** B.1.1 — test-key-rsa (RSASSA-PKCS1-v1_5), PKCS#1 PEM. */
export const RSA_PUBLIC_KEY_PKCS1 = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
-----END RSA PUBLIC KEY-----`;

export const RSA_PRIVATE_KEY_PKCS1 = `-----BEGIN RSA PRIVATE KEY-----
MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
-----END RSA PRIVATE KEY-----`;

/** B.1.2 — test-key-rsa-pss (RSA-PSS), SPKI / PKCS#8 PEM. */
export const RSA_PSS_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----`;

export const RSA_PSS_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
rOjr9w349JooGXhOxbu8nOxX
-----END PRIVATE KEY-----`;

/** B.1.3 — test-key-ecc-p256 (ECDSA P-256), SPKI / SEC1 PEM. */
export const ECC_P256_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----`;

export const ECC_P256_PRIVATE_KEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----`;

/** B.1.4 — test-key-ed25519 (Ed25519), SPKI / PKCS#8 PEM. */
export const ED25519_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----`;

export const ED25519_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`;

/** B.1.5 — test-shared-secret (HMAC), 64 random bytes, Base64. */
export const SHARED_SECRET_BASE64 =
  "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==";

/** Aggregate keyed by RFC `keyid`. */
export const KEYS = {
  "test-key-rsa": { public: RSA_PUBLIC_KEY_PKCS1, private: RSA_PRIVATE_KEY_PKCS1 },
  "test-key-rsa-pss": { public: RSA_PSS_PUBLIC_KEY, private: RSA_PSS_PRIVATE_KEY },
  "test-key-ecc-p256": { public: ECC_P256_PUBLIC_KEY, private: ECC_P256_PRIVATE_KEY },
  "test-key-ed25519": { public: ED25519_PUBLIC_KEY, private: ED25519_PRIVATE_KEY },
  "test-shared-secret": { secretBase64: SHARED_SECRET_BASE64 },
} as const;

// ---------------------------------------------------------------------------
// B.2 Messages
// ---------------------------------------------------------------------------

export const REQUEST_CONTENT_DIGEST =
  "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:";

export const RESPONSE_CONTENT_DIGEST =
  "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:";

/** test-request (RFC 9421 §B.2). */
export const TEST_REQUEST = {
  method: "POST",
  url: "https://example.com/foo?param=Value&Pet=dog",
  headers: {
    host: "example.com",
    date: "Tue, 20 Apr 2021 02:07:55 GMT",
    "content-type": "application/json",
    "content-digest": REQUEST_CONTENT_DIGEST,
    "content-length": "18",
  },
  body: '{"hello": "world"}',
} as const;

/** test-response (RFC 9421 §B.2). */
export const TEST_RESPONSE = {
  status: 200,
  headers: {
    date: "Tue, 20 Apr 2021 02:07:56 GMT",
    "content-type": "application/json",
    "content-digest": RESPONSE_CONTENT_DIGEST,
    "content-length": "23",
  },
  body: '{"message": "good dog"}',
} as const;

/** B.3 TLS-terminating-proxy internal request bearing the Client-Cert field. */
export const PROXY_CLIENT_CERT =
  "MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKDBJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=";

export const PROXY_REQUEST = {
  method: "POST",
  url: "https://service.internal.example/foo?param=Value&Pet=dog",
  headers: {
    host: "service.internal.example",
    date: "Tue, 20 Apr 2021 02:07:55 GMT",
    "content-type": "application/json",
    "content-length": "18",
    "client-cert": `:${PROXY_CLIENT_CERT}:`,
  },
  body: '{"hello": "world"}',
} as const;

// ---------------------------------------------------------------------------
// §2.5 Non-normative worked example (Figure 1)
// ---------------------------------------------------------------------------

/** Signature base from RFC 9421 §2.5, Figure 1 (no trailing newline). */
export const SECTION_2_5_SIGNATURE_BASE = [
  '"@method": POST',
  '"@authority": example.com',
  '"@path": /foo',
  `"content-digest": ${REQUEST_CONTENT_DIGEST}`,
  '"content-length": 18',
  '"content-type": application/json',
  '"@signature-params": ("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884473;keyid="test-key-rsa-pss"',
].join("\n");

// ---------------------------------------------------------------------------
// B.2 / B.3 Signature vectors
// ---------------------------------------------------------------------------

export interface SignatureVector {
  /** Signature label (e.g. `sig-b21`). */
  readonly label: string;
  /** RFC section the vector is drawn from. */
  readonly section: string;
  /** Registered algorithm identifier. */
  readonly algorithm: SignatureAlgorithm;
  /** `keyid` parameter / lookup key. */
  readonly keyid: string;
  /**
   * Whether the algorithm is deterministic. Deterministic vectors
   * (HMAC, Ed25519) can be re-derived byte-for-byte; non-deterministic ones
   * (RSA-PSS, ECDSA) can only be verified against the published signature.
   */
  readonly deterministic: boolean;
  /** The exact signature base string (LF-separated, no trailing newline). */
  readonly signatureBase: string;
  /** The `Signature-Input` field value (without the field name). */
  readonly signatureInput: string;
  /** The base64 signature value (the bytes between the `:` SFV delimiters). */
  readonly signature: string;
}

export const SIGNATURE_VECTORS: readonly SignatureVector[] = [
  {
    label: "sig-b21",
    section: "B.2.1",
    algorithm: "rsa-pss-sha512",
    keyid: "test-key-rsa-pss",
    deterministic: false,
    signatureBase:
      '"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
    signatureInput:
      '();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
    signature:
      "d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==",
  },
  {
    label: "sig-b22",
    section: "B.2.2",
    algorithm: "rsa-pss-sha512",
    keyid: "test-key-rsa-pss",
    deterministic: false,
    signatureBase: [
      '"@authority": example.com',
      `"content-digest": ${REQUEST_CONTENT_DIGEST}`,
      '"@query-param";name="Pet": dog',
      '"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
    ].join("\n"),
    signatureInput:
      '("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
    signature:
      "LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==",
  },
  {
    label: "sig-b23",
    section: "B.2.3",
    algorithm: "rsa-pss-sha512",
    keyid: "test-key-rsa-pss",
    deterministic: false,
    signatureBase: [
      '"date": Tue, 20 Apr 2021 02:07:55 GMT',
      '"@method": POST',
      '"@path": /foo',
      '"@query": ?param=Value&Pet=dog',
      '"@authority": example.com',
      '"content-type": application/json',
      `"content-digest": ${REQUEST_CONTENT_DIGEST}`,
      '"content-length": 18',
      '"@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"',
    ].join("\n"),
    signatureInput:
      '("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"',
    signature:
      "bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==",
  },
  {
    label: "sig-b24",
    section: "B.2.4",
    algorithm: "ecdsa-p256-sha256",
    keyid: "test-key-ecc-p256",
    deterministic: false,
    signatureBase: [
      '"@status": 200',
      '"content-type": application/json',
      `"content-digest": ${RESPONSE_CONTENT_DIGEST}`,
      '"content-length": 23',
      '"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
    ].join("\n"),
    signatureInput:
      '("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
    signature:
      "wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==",
  },
  {
    label: "sig-b25",
    section: "B.2.5",
    algorithm: "hmac-sha256",
    keyid: "test-shared-secret",
    deterministic: true,
    signatureBase: [
      '"date": Tue, 20 Apr 2021 02:07:55 GMT',
      '"@authority": example.com',
      '"content-type": application/json',
      '"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
    ].join("\n"),
    signatureInput:
      '("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
    signature: "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=",
  },
  {
    label: "sig-b26",
    section: "B.2.6",
    algorithm: "ed25519",
    keyid: "test-key-ed25519",
    deterministic: true,
    signatureBase: [
      '"date": Tue, 20 Apr 2021 02:07:55 GMT',
      '"@method": POST',
      '"@path": /foo',
      '"@authority": example.com',
      '"content-type": application/json',
      '"content-length": 18',
      '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
    ].join("\n"),
    signatureInput:
      '("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
    signature:
      "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==",
  },
  {
    label: "ttrp",
    section: "B.3",
    algorithm: "ecdsa-p256-sha256",
    keyid: "test-key-ecc-p256",
    deterministic: false,
    signatureBase: [
      '"@path": /foo',
      '"@query": ?param=Value&Pet=dog',
      '"@method": POST',
      '"@authority": service.internal.example',
      `"client-cert": :${PROXY_CLIENT_CERT}:`,
      '"@signature-params": ("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"',
    ].join("\n"),
    signatureInput:
      '("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"',
    signature:
      "xVMHVpawaAC/0SbHrKRs9i8I3eOs5RtTMGCWXm/9nvZzoHsIg6Mce9315T6xoklyy0yzhD9ah4JHRwMLOgmizw==",
  },
] as const;

/** Lookup a vector by its label. */
export function vectorByLabel(label: string): SignatureVector {
  const found = SIGNATURE_VECTORS.find((v) => v.label === label);
  if (!found) {
    throw new Error(`No RFC 9421 vector with label ${label}`);
  }
  return found;
}
```

---

