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
