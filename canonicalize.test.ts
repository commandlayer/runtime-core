/**
 * Canonicalization tests — runtime-core
 *
 * These tests run the CANONICAL_TEST_VECTORS that all downstream repos
 * import and run in their own test suites. If these pass here and pass
 * in agent-sdk, verifyagent, mcp-server etc., canonicalization is aligned.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { canonicalize, CANONICAL_TEST_VECTORS } from "../src/canonicalize.js";

describe("canonicalize — test vectors", () => {
  for (const vector of CANONICAL_TEST_VECTORS) {
    it(vector.description, () => {
      const result = canonicalize(vector.input);
      assert.strictEqual(result, vector.expected);
    });
  }
});

describe("canonicalize — error cases", () => {
  it("throws on Infinity", () => {
    assert.throws(() => canonicalize({ x: Infinity }), /non-finite number/);
  });

  it("throws on NaN", () => {
    assert.throws(() => canonicalize({ x: NaN }), /non-finite number/);
  });

  it("throws on Date objects", () => {
    assert.throws(() => canonicalize({ d: new Date() }), /Date objects/);
  });

  it("throws on BigInt", () => {
    assert.throws(() => canonicalize({ n: BigInt(1) }), /BigInt/);
  });

  it("throws on circular reference", () => {
    const obj: Record<string, unknown> = {};
    obj.self = obj;
    assert.throws(() => canonicalize(obj), /circular reference/);
  });

  it("skips undefined values", () => {
    const result = canonicalize({ a: 1, b: undefined, c: 3 });
    assert.strictEqual(result, '{"a":1,"c":3}');
  });

  it("undefined in array becomes null", () => {
    const result = canonicalize([1, undefined, 3]);
    assert.strictEqual(result, "[1,null,3]");
  });
});

describe("canonicalize — determinism", () => {
  it("same output for same input regardless of insertion order", () => {
    const a = canonicalize({ z: 1, a: 2 });
    const b = canonicalize({ a: 2, z: 1 });
    assert.strictEqual(a, b);
  });

  it("nested keys are also sorted", () => {
    const result = canonicalize({ outer: { z: 9, a: 1 } });
    assert.strictEqual(result, '{"outer":{"a":1,"z":9}}');
  });
});
