/**
 * Canonicalization tests — runtime-core
 *
 * These tests run the CANONICAL_TEST_VECTORS that all downstream repos
 * import and run in their own test suites. If these pass here and pass
 * in agent-sdk, verifyagent, mcp-server etc., canonicalization is aligned.
 */

import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
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

describe("canonicalize — SHA-256 audit test vector", () => {
  /**
   * CRITICAL PATH: The audit protocol mandates that the SHA-256 digest of the
   * canonical form of {"verb":"verify","family":"trust","version":"1.0.0"}
   * is computed and verified against a known value.
   *
   * Canonical form (keys sorted): {"family":"trust","verb":"verify","version":"1.0.0"}
   * SHA-256 (hex): 3c3e2e6f63b02c1dc4d0dc0f6429bcef5fe27f11059c856218a52a4f43f90e44
   *
   * This test locks the canonicalization algorithm to a concrete byte-level
   * output and proves the SHA-256 is deterministic across Node.js versions.
   */
  it("SHA-256 of canonical audit vector matches known digest", () => {
    const input = { verb: "verify", family: "trust", version: "1.0.0" };
    const canonical = canonicalize(input);

    // Verify the canonical string itself first
    assert.strictEqual(
      canonical,
      '{"family":"trust","verb":"verify","version":"1.0.0"}',
      "canonical form must have keys sorted lexicographically"
    );

    // Compute SHA-256 of the UTF-8 bytes of the canonical string
    const digest = createHash("sha256")
      .update(canonical, "utf8")
      .digest("hex");

    // Known SHA-256 digest — locked as the protocol audit test vector.
    // If this fails, canonicalization has changed and protocol version must bump.
    assert.strictEqual(
      digest,
      "3c3e2e6f63b02c1dc4d0dc0f6429bcef5fe27f11059c856218a52a4f43f90e44",
      "SHA-256 of canonical audit vector must match the known protocol digest"
    );
  });

  it("audit vector SHA-256 matches CANONICAL_TEST_VECTORS entry", () => {
    // Cross-check: the sha256 field in CANONICAL_TEST_VECTORS must match
    // what we compute at runtime, ensuring the exported constant is correct.
    const auditVector = CANONICAL_TEST_VECTORS.find(
      (v) => v.description === "audit protocol vector: verb/family/version"
    );
    assert.ok(auditVector, "audit vector must exist in CANONICAL_TEST_VECTORS");

    const canonical = canonicalize(auditVector.input);
    assert.strictEqual(canonical, auditVector.expected);

    const digest = createHash("sha256").update(canonical, "utf8").digest("hex");
    // Type assertion needed because not all vectors have sha256 field
    const vectorWithHash = auditVector as typeof auditVector & { sha256: string };
    assert.strictEqual(
      digest,
      vectorWithHash.sha256,
      "runtime-computed SHA-256 must match the sha256 field in CANONICAL_TEST_VECTORS"
    );
  });
});
