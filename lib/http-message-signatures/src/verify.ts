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
import { isSupportedAlgorithm } from "./crypto.js";
import {
  ByteSequence,
  parseDictionary,
  type Dictionary,
  type InnerList,
  type ListMember,
} from "./sfv.js";
import type {
  HttpMessage,
  SignatureAlgorithm,
  VerifierPolicy,
  VerifyingKey,
  VerifyOptions,
  VerifyResult,
} from "./types.js";

const te = new TextEncoder();

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

function checkPolicy(
  sig: ParsedSignature,
  policy: VerifierPolicy,
  now: number,
): string | undefined {
  const tolerance = policy.clockTolerance ?? 5;

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
