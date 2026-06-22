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
