/**
 * Public type surface for RFC 9421 HTTP Message Signatures.
 *
 * RFC 9421 mapping:
 *  - §2     message component model
 *  - §2.3   @signature-params (created/expires/nonce/alg/keyid/tag)
 *  - §3.3   signature algorithm identifiers (HTTP Signature Algorithms registry, §6.2)
 *  - §3.1   signing
 *  - §3.2   verification + policy
 */

/** WebCrypto key handle (browsers, Deno, edge runtimes, Node 18+). */
export type CryptoKey = globalThis.CryptoKey;

/**
 * Registered signature algorithms (RFC 9421 §3.3 / §6.2.2).
 * There is intentionally no "default" — callers must choose explicitly.
 */
export type SignatureAlgorithm =
  | "rsa-pss-sha512"
  | "rsa-v1_5-sha256"
  | "ecdsa-p256-sha256"
  | "ecdsa-p384-sha384"
  | "ed25519"
  | "hmac-sha256";

/** HTTP field values keyed by lowercase field name; arrays model repeated fields. */
export type HttpHeaders = Record<string, string | string[] | undefined>;

/** Normalized request component context (RFC 9421 §2.2, §1.2). */
export interface RequestLike {
  method: string;
  url: string | URL;
  headers: HttpHeaders;
  /** Trailer-section fields, for components carrying `;tr` (RFC 9421 §2.1.1). */
  trailers?: HttpHeaders;
}

/** Normalized response component context (RFC 9421 §2.2.9, §2.4 for `;req`). */
export interface ResponseLike {
  status: number;
  headers: HttpHeaders;
  /** Trailer-section fields, for components carrying `;tr` (RFC 9421 §2.1.1). */
  trailers?: HttpHeaders;
  /** The request that produced this response, for components carrying `;req`. */
  relatedRequest?: RequestLike;
}

/** Either side of an HTTP exchange may be signed/verified. */
export type HttpMessage = RequestLike | ResponseLike;

/** Parameters that may decorate a covered component identifier (RFC 9421 §2.1). */
export interface ComponentParams {
  /** `;key=` — select a Dictionary member of a structured field. */
  key?: string;
  /** `;name=` — select a named query parameter (`@query-param`). */
  name?: string;
  /** `;sf` — re-serialize the field as strict Structured Fields. */
  sf?: boolean;
  /** `;bs` — byte-sequence-wrap each field line (defends against value splitting). */
  bs?: boolean;
  /** `;tr` — the component is a trailer field. */
  tr?: boolean;
  /** `;req` — bind to the related request (response signatures only). */
  req?: boolean;
}

/** A covered component identifier: a name plus optional parameters. */
export interface ComponentIdentifier {
  /** e.g. `"@method"`, `"@query-param"`, `"content-digest"`. */
  name: string;
  params?: ComponentParams;
}

/** A covered component may be a bare name or a fully-specified identifier. */
export type ComponentSpec = string | ComponentIdentifier;

/** The `@signature-params` metadata (RFC 9421 §2.3). */
export interface SignatureParameters {
  /** Unix seconds; `null`/omitted means no `created`. */
  created?: number | null;
  /** Unix seconds; `null`/omitted means no `expires`. */
  expires?: number | null;
  /** Opaque nonce (SFV String). */
  nonce?: string;
  /** Explicit algorithm tag (SFV String). */
  alg?: SignatureAlgorithm;
  /** Key identifier (SFV String). */
  keyid?: string;
  /** Application-specific tag (SFV String). */
  tag?: string;
}

/**
 * A signer abstraction. Implementations wrap key material and produce the raw
 * signature bytes for a signature base (RFC 9421 §3.3 wire encodings apply).
 */
export interface SigningKey {
  alg: SignatureAlgorithm;
  keyid?: string;
  sign(data: Uint8Array): Promise<Uint8Array> | Uint8Array;
}

/** A verifier abstraction bound to trusted key material. */
export interface VerifyingKey {
  /** Algorithms this key is permitted to verify (downgrade defense, §3.2). */
  algs: readonly SignatureAlgorithm[];
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean> | boolean;
}

/** Options accepted by {@link signMessage} (TSD §4.1). */
export interface SignOptions {
  /** Signer or raw WebCrypto private/secret key. */
  key: SigningKey | CryptoKey;
  /** Algorithm to use; required when `key` is a raw CryptoKey. */
  alg?: SignatureAlgorithm;
  /** Key identifier emitted in `@signature-params`. */
  keyid?: string;
  /** Ordered covered components (order is significant and preserved). */
  components: ComponentSpec[];
  /** Signature parameters (created/expires/nonce/tag/alg). */
  params?: SignatureParameters;
  /** Signature label used in the `Signature` / `Signature-Input` dictionaries. */
  label?: string;
}

/** The header pair produced by {@link signMessage}. */
export interface SignResult {
  /** Value for the `Signature-Input` HTTP field. */
  signatureInput: string;
  /** Value for the `Signature` HTTP field. */
  signature: string;
}

/** Resolves trusted key material from the signature's asserted identity. */
export type KeyLookup = (
  keyid: string | undefined,
  alg: SignatureAlgorithm | undefined,
) => Promise<VerifyingKey | null | undefined> | VerifyingKey | null | undefined;

/** Verifier policy (RFC 9421 §3.2, §7.2; TSD §3.5). */
export interface VerifierPolicy {
  /** Components that MUST be covered; missing any -> reject. */
  requiredCoveredComponents?: ComponentSpec[];
  /** Max accepted age of `created` in seconds. */
  maxAgeSeconds?: number;
  /** Allowed algorithms; anything else -> reject. */
  allowedAlgorithms?: readonly SignatureAlgorithm[];
  /** Symmetric clock skew grace in seconds (Amendment A2; default 5). */
  clockTolerance?: number;
  /** Whether a non-expired `expires` is mandatory. */
  requireExpires?: boolean;
  /** Optional replay hook; return false to reject the nonce. */
  nonceVerify?: (nonce: string | undefined) => Promise<boolean> | boolean;
  /** Optional tag match. */
  tag?: string;
}

/** Options accepted by {@link verifyMessage} (TSD §4.1). */
export interface VerifyOptions {
  keyLookup: KeyLookup;
  policy?: VerifierPolicy;
  /** Verify a specific signature label; default verifies all present. */
  label?: string;
  /** Injectable clock for deterministic tests (Unix seconds). */
  now?: () => number;
}

/** Structured verification outcome (never throws on a merely-invalid signature). */
export interface VerifyResult {
  valid: boolean;
  label?: string;
  reason?: string;
  coveredComponents?: string[];
}
