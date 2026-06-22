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
