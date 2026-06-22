/**
 * Hardening suite — the red-team fixes (RFC 9421 §2.2.8, §2.3, §3.2, §7.2).
 *
 *  F1  Strict @signature-params typing: created/expires MUST be Integer;
 *      alg/keyid/nonce/tag MUST be String. Present-but-wrong-type is malformed
 *      (closes algorithm-confusion-by-token and timestamp-bypass-by-type).
 *  F2  policy.nonceVerify is actually invoked (replay defense).
 *  F3  @query-param re-encodes via percent-encoding (%20 for space), not '+'.
 *  F4  allowedAlgorithms with a signature that declares no alg is rejected,
 *      and maxAgeSeconds with no created timestamp is rejected.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { signMessage } from "../src/sign.js";
import { verifyMessage } from "../src/verify.js";
import { createSignatureBase } from "../src/base.js";
import { MalformedSignatureError } from "../src/errors.js";
import type {
  ComponentSpec,
  RequestLike,
  SignatureAlgorithm,
  SignatureParameters,
} from "../src/types.js";
import { TEST_REQUEST } from "./fixtures/rfc9421-vectors.js";
import { generateSigner } from "./helpers/crypto.js";

const COMPONENTS: ComponentSpec[] = ["@method", "@authority", "@path"];
const CREATED = 1618884473;

async function makeSignedMessage(
  params: SignatureParameters,
  alg: SignatureAlgorithm = "ed25519",
  keyid = "k1",
) {
  const { signing, verifying } = await generateSigner(alg, keyid);
  const { signatureInput, signature } = await signMessage(TEST_REQUEST, {
    key: signing,
    components: COMPONENTS,
    params,
    label: "sig",
  });
  const message = {
    ...TEST_REQUEST,
    headers: { ...TEST_REQUEST.headers, "signature-input": signatureInput, signature },
  };
  return { message, verifying };
}

function withRawSig(input: string, sig = "sig=:AAAA:") {
  return {
    ...TEST_REQUEST,
    headers: { ...TEST_REQUEST.headers, "signature-input": input, signature: sig },
  };
}

describe("F1: strict @signature-params typing (RFC 9421 §2.3)", () => {
  const malformed: [string, string][] = [
    ["created as a String", 'sig=("@method");created="1618884473";keyid="k"'],
    ["created as a Decimal", 'sig=("@method");created=1618884473.5;keyid="k"'],
    ["expires as a String", 'sig=("@method");created=1;expires="99"'],
    ["keyid as an Integer", 'sig=("@method");created=1;keyid=42'],
    ["alg as a bare Token (downgrade attempt)", 'sig=("@method");created=1;alg=ed25519'],
    ["nonce as a Boolean", 'sig=("@method");created=1;nonce=?1'],
    ["tag as an Integer", 'sig=("@method");created=1;tag=5'],
  ];
  for (const [name, input] of malformed) {
    test(`rejects ${name}`, async () => {
      await assert.rejects(
        verifyMessage(withRawSig(input), { keyLookup: () => undefined, now: () => CREATED }),
        MalformedSignatureError,
      );
    });
  }
});

describe("F2: nonceVerify is enforced (RFC 9421 §7.2.2)", () => {
  test("a rejected nonce fails verification and the hook sees the nonce", async () => {
    const { message, verifying } = await makeSignedMessage({ created: CREATED, nonce: "abc" });
    let seen: string | undefined = "UNSET";
    const result = await verifyMessage(message, {
      keyLookup: () => verifying,
      now: () => CREATED,
      policy: {
        nonceVerify: (n) => {
          seen = n;
          return false;
        },
      },
    });
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /nonce/);
    assert.equal(seen, "abc");
  });

  test("an accepting nonce hook allows an otherwise-valid signature", async () => {
    const { message, verifying } = await makeSignedMessage({ created: CREATED, nonce: "abc" });
    const result = await verifyMessage(message, {
      keyLookup: () => verifying,
      now: () => CREATED,
      policy: { nonceVerify: async () => true },
    });
    assert.equal(result.valid, true);
  });

  test("a throwing nonce hook fails closed", async () => {
    const { message, verifying } = await makeSignedMessage({ created: CREATED, nonce: "abc" });
    const result = await verifyMessage(message, {
      keyLookup: () => verifying,
      now: () => CREATED,
      policy: {
        nonceVerify: () => {
          throw new Error("nonce store unavailable");
        },
      },
    });
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /nonce verification errored/);
  });
});

describe("F4: policy cannot be silently waived", () => {
  test("allowedAlgorithms with no declared alg is rejected", async () => {
    const { message, verifying } = await makeSignedMessage({ created: CREATED });
    const result = await verifyMessage(message, {
      keyLookup: () => verifying,
      now: () => CREATED,
      policy: { allowedAlgorithms: ["ed25519"] },
    });
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /does not state one/);
  });

  test("allowedAlgorithms admits a matching declared alg", async () => {
    const { message, verifying } = await makeSignedMessage({ created: CREATED, alg: "ed25519" });
    const result = await verifyMessage(message, {
      keyLookup: () => verifying,
      now: () => CREATED,
      policy: { allowedAlgorithms: ["ed25519"] },
    });
    assert.equal(result.valid, true);
  });

  test("allowedAlgorithms rejects an off-list declared alg", async () => {
    const { message, verifying } = await makeSignedMessage({ created: CREATED, alg: "ed25519" });
    const result = await verifyMessage(message, {
      keyLookup: () => verifying,
      now: () => CREATED,
      policy: { allowedAlgorithms: ["hmac-sha256"] },
    });
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /not allowed by policy/);
  });

  test("maxAgeSeconds with no created timestamp is rejected", async () => {
    const { message, verifying } = await makeSignedMessage({ nonce: "n" });
    const result = await verifyMessage(message, {
      keyLookup: () => verifying,
      now: () => CREATED,
      policy: { maxAgeSeconds: 300 },
    });
    assert.equal(result.valid, false);
    assert.match(result.reason ?? "", /no created timestamp/);
  });
});

describe("F3: @query-param re-encoding (RFC 9421 §2.2.8)", () => {
  const req: RequestLike = {
    method: "GET",
    url:
      "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value" +
      "&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something",
    headers: {},
  };

  function qpLine(name: string): string {
    const base = createSignatureBase(req, [{ name: "@query-param", params: { name } }], {
      created: CREATED,
    });
    return base.split("\n")[0]!;
  }

  test("space and newline are percent-encoded as %20/%0A (not '+')", () => {
    assert.equal(
      qpLine("var"),
      '"@query-param";name="var": this%20is%20a%20big%0Amultiline%20value',
    );
  });

  test("a '+' in the source is parsed as a space and re-encoded as %20", () => {
    assert.equal(qpLine("bar"), '"@query-param";name="bar": with%20plus%20whitespace');
  });

  test("a percent-encoded name matches and its value re-encodes", () => {
    assert.equal(
      qpLine("fa%C3%A7ade%22%3A%20"),
      '"@query-param";name="fa%C3%A7ade%22%3A%20": something',
    );
  });

  test("a named parameter that is not present is an error", () => {
    assert.throws(() => qpLine("missing"));
  });
});
