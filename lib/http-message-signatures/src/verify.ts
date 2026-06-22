/**
 * Public verifier — subpath `/verify` (RFC 9421 §3.2, §4.1–4.3).
 *
 * Returns a structured result; it never throws on a merely-invalid signature.
 * It throws only when the input is malformed (TSD §3.1 boundary).
 *
 * NOTE: scaffold only — orchestration is implemented in Layer 3 (Step 6).
 */

import { NotImplementedError } from "./errors.js";
import type { HttpMessage, VerifyOptions, VerifyResult } from "./types.js";

/**
 * Verify the signature(s) on an HTTP message against trusted key material
 * resolved through `options.keyLookup`, then apply verifier policy.
 */
export async function verifyMessage(
  _message: HttpMessage,
  _options: VerifyOptions,
): Promise<VerifyResult> {
  throw new NotImplementedError("verifyMessage");
}
