/**
 * Public signer — subpath `/sign` (RFC 9421 §3.1, §4.1–4.2).
 *
 * NOTE: scaffold only — orchestration is implemented in Layer 3 (Step 6).
 */

import { NotImplementedError } from "./errors.js";
import type {
  ComponentSpec,
  HttpMessage,
  SignOptions,
  SignResult,
  SignatureParameters,
} from "./types.js";

/**
 * Build the RFC 9421 signature base byte string (§2.5) for the given message,
 * covered components, and signature parameters. Low-level escape hatch.
 */
export function createSignatureBase(
  _message: HttpMessage,
  _components: ComponentSpec[],
  _params: SignatureParameters,
): string {
  throw new NotImplementedError("createSignatureBase");
}

/**
 * Sign an HTTP message, returning the `Signature-Input` / `Signature` header
 * values (RFC 9421 §3.1).
 */
export async function signMessage(
  _message: HttpMessage,
  _options: SignOptions,
): Promise<SignResult> {
  throw new NotImplementedError("signMessage");
}
