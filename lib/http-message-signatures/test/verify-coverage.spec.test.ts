/**
 * Coverage suite — verification pipeline (`src/verify.ts`).
 * Drives every parse-error branch, every checkPolicy rejection, and the
 * verifyMessage label/key/base/verify outcomes. Policy rejections are reached
 * before key lookup, so most cases need only a well-typed (not valid) signature.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { verifyMessage, createVerifyingKey } from "../src/verify.js";
import { MalformedSignatureError, UnsupportedAlgorithmError } from "../src/errors.js";
import type { HttpMessage, RequestLike, VerifierPolicy, VerifyingKey } from "../src/types.js";

const CREATED = 1618884473;
const REQ: RequestLike = { method: "POST", url: "https://example.com/foo", headers: {} };

function withSig(input?: string, signature?: string): HttpMessage {
  const headers: Record<string, string> = {};
  if (input !== undefined) headers["signature-input"] = input;
  if (signature !== undefined) headers["signature"] = signature;
  return { ...REQ, headers };
}

const SIG = "sig=:AAAA:";
const noKey = { keyLookup: () => undefined, now: () => CREATED };

describe("parseSignatures: malformed envelopes", () => {
  const malformed: [string, HttpMessage][] = [
    ["Signature without Signature-Input", withSig(undefined, SIG)],
    ["neither field present", withSig(undefined, undefined)],
    ["Signature-Input without Signature", withSig('sig=("@method")', undefined)],
    ["unparseable field", withSig("((", SIG)],
    ["member is not an inner list", withSig("sig=5", SIG)],
    ["no Signature value for the label", withSig('sig=("@method")', "other=:AAAA:")],
    ["Signature value is not a byte sequence", withSig('sig=("@method")', "sig=5")],
  ];
  for (const [name, message] of malformed) {
    test(`rejects: ${name}`, async () => {
      await assert.rejects(verifyMessage(message, noKey), MalformedSignatureError);
    });
  }

  test("rejects an unsupported algorithm token", async () => {
    await assert.rejects(
      verifyMessage(withSig('sig=("@method");alg="made-up-alg"', SIG), noKey),
      UnsupportedAlgorithmError,
    );
  });
});

describe("checkPolicy: each rejection reason", () => {
  async function reasonFor(input: string, policy: VerifierPolicy): Promise<string> {
    const result = await verifyMessage(withSig(input, SIG), { ...noKey, policy });
    assert.equal(result.valid, false);
    return result.reason ?? "";
  }

  test("created timestamp in the future", async () => {
    assert.match(await reasonFor(`sig=("@method");created=${CREATED + 1000}`, {}), /in the future/);
  });

  test("exceeds the maximum accepted age", async () => {
    assert.match(
      await reasonFor(`sig=("@method");created=${CREATED - 1000}`, { maxAgeSeconds: 10 }),
      /maximum accepted age/,
    );
  });

  test("expired signature", async () => {
    assert.match(await reasonFor(`sig=("@method");expires=${CREATED - 100}`, {}), /has expired/);
  });

  test("requireExpires with no expires", async () => {
    assert.match(
      await reasonFor(`sig=("@method");created=${CREATED}`, { requireExpires: true }),
      /requires an expires/,
    );
  });

  test("tag does not match policy", async () => {
    assert.match(
      await reasonFor(`sig=("@method");created=${CREATED};tag="a"`, { tag: "b" }),
      /tag does not match/,
    );
  });

  test("required covered component missing", async () => {
    assert.match(
      await reasonFor(`sig=("@method");created=${CREATED}`, { requiredCoveredComponents: ["@path"] }),
      /required covered component/,
    );
  });

  test("invalid clockTolerance is rejected deterministically", async () => {
    for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
      await assert.rejects(
        verifyMessage(withSig(`sig=("@method");created=${CREATED}`, SIG), {
          ...noKey,
          policy: { clockTolerance: bad },
        }),
        /clockTolerance must be a finite, non-negative number/,
      );
    }
  });
});

describe("verifyMessage: label, key, base, and verify outcomes", () => {
  function key(algs: VerifyingKey["algs"], verify: VerifyingKey["verify"]): VerifyingKey {
    return { algs, verify };
  }

  test("an unknown requested label is malformed", async () => {
    await assert.rejects(
      verifyMessage(withSig(`sig=("@method");created=${CREATED}`, SIG), { ...noKey, label: "missing" }),
      MalformedSignatureError,
    );
  });

  test("an empty signature set has nothing to verify", async () => {
    await assert.rejects(verifyMessage(withSig("", ""), noKey), MalformedSignatureError);
  });

  test("no key resolved", async () => {
    const result = await verifyMessage(withSig(`sig=("@method");created=${CREATED}`, SIG), {
      keyLookup: () => null,
      now: () => CREATED,
    });
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /no key resolved/);
  });

  test("key lookup that throws fails closed", async () => {
    const result = await verifyMessage(withSig(`sig=("@method");created=${CREATED}`, SIG), {
      keyLookup: () => {
        throw new Error("registry offline");
      },
      now: () => CREATED,
    });
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /key lookup failed/);
  });

  test("key that does not permit the declared algorithm", async () => {
    const result = await verifyMessage(
      withSig(`sig=("@method");created=${CREATED};alg="ed25519"`, SIG),
      { keyLookup: () => key(["hmac-sha256"], async () => true), now: () => CREATED },
    );
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /does not permit algorithm ed25519/);
  });

  test("a base that cannot be built fails closed", async () => {
    const result = await verifyMessage(withSig('sig=("x-absent")', SIG), {
      keyLookup: () => key([], async () => true),
      now: () => CREATED,
    });
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /cannot build signature base/);
  });

  test("a verify hook returning false reports verification failure", async () => {
    const result = await verifyMessage(withSig(`sig=("@method");created=${CREATED}`, SIG), {
      keyLookup: () => key([], async () => false),
      now: () => CREATED,
    });
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /signature verification failed/);
  });

  test("a throwing verify hook fails closed", async () => {
    const result = await verifyMessage(withSig(`sig=("@method");created=${CREATED}`, SIG), {
      keyLookup: () =>
        key([], async () => {
          throw new Error("backend boom");
        }),
      now: () => CREATED,
    });
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /signature verification failed/);
  });
});

describe("createVerifyingKey", () => {
  test("rejects an unsupported algorithm", () => {
    assert.throws(
      () => createVerifyingKey({} as unknown as CryptoKey, "rsa-pss-sha384" as never),
      UnsupportedAlgorithmError,
    );
  });

  test("binds the permitted algorithm set to the single algorithm", () => {
    const vk = createVerifyingKey({} as unknown as CryptoKey, "ed25519");
    assert.deepEqual(vk.algs, ["ed25519"]);
  });
});
