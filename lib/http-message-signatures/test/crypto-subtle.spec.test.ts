/**
 * Coverage suite — runtime WebCrypto resolution (`src/crypto.ts` getSubtle).
 * Runs in its own process (one file per worker) so the module-level cache is
 * empty when the fallback branch is exercised first.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { getSubtle } from "../src/crypto.js";

test("getSubtle falls back to node WebCrypto when globalThis.crypto is absent", async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  try {
    Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true });
    const subtle = await getSubtle();
    assert.equal(typeof subtle.sign, "function");
    // Second call returns the cached implementation.
    assert.equal(await getSubtle(), subtle);
  } finally {
    if (descriptor) Object.defineProperty(globalThis, "crypto", descriptor);
  }
});
