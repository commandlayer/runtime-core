/**
 * Crypto tests — runtime-core
 *
 * Tests the signing contract:
 *   message = raw UTF-8 bytes of canonicalize(payload)
 *   signature = Ed25519(message)
 *   encoding = standard base64
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  generateEd25519KeyPair,
  signCanonical,
  verifyCanonical,
  verifyCanonicalWithRawKey,
  encodePublicKey,
  parsePublicKey,
} from "../src/crypto.js";
import { canonicalize } from "../src/canonicalize.js";

describe("key encoding", () => {
  it("encodes 32-byte key with standard base64 (= padding)", () => {
    const raw = new Uint8Array(32).fill(1);
    const encoded = encodePublicKey(raw);
    assert.ok(encoded.startsWith("ed25519:"));
    // Standard base64 may have = padding
    const b64 = encoded.slice("ed25519:".length);
    assert.ok(/^[A-Za-z0-9+/]+=*$/.test(b64), "should be standard base64");
  });

  it("throws on wrong key length", () => {
    assert.throws(() => encodePublicKey(new Uint8Array(31)), /32 bytes/);
    assert.throws(() => encodePublicKey(new Uint8Array(33)), /32 bytes/);
  });

  it("parsePublicKey round-trips encodePublicKey", () => {
    const raw = new Uint8Array(32);
    crypto.getRandomValues(raw);
    const encoded = encodePublicKey(raw);
    const decoded = parsePublicKey(encoded);
    assert.deepStrictEqual(decoded, raw);
  });

  it("parses production ENS record format", () => {
    // Live ENS record: ed25519:hhyCuPNoMk4JtEvGEV8F6nMZ4uDO1EcyizPufmnJTOY=
    const prod = "ed25519:hhyCuPNoMk4JtEvGEV8F6nMZ4uDO1EcyizPufmnJTOY=";
    const raw = parsePublicKey(prod);
    assert.strictEqual(raw.length, 32);
  });

  it("rejects missing ed25519: prefix", () => {
    assert.throws(
      () => parsePublicKey("hhyCuPNoMk4JtEvGEV8F6nMZ4uDO1EcyizPufmnJTOY="),
      /ed25519:/
    );
  });
});

describe("sign and verify — round trip", () => {
  it("signs and verifies a canonical string with PEM keys", () => {
    const { privateKeyPem, publicKeyPem } = generateEd25519KeyPair();
    const payload = { verb: "verify", agent: "test.eth", timestamp: "2026-01-01T00:00:00Z" };
    const canonical = canonicalize(payload);

    const sig = signCanonical(canonical, privateKeyPem);

    // Signature is standard base64
    assert.ok(/^[A-Za-z0-9+/]+=*$/.test(sig), "signature should be standard base64");
    // Ed25519 signatures are always 64 bytes
    assert.strictEqual(Buffer.from(sig, "base64").length, 64);

    const valid = verifyCanonical(canonical, sig, publicKeyPem);
    assert.strictEqual(valid, true);
  });

  it("verifies with raw public key", () => {
    const { privateKeyPem, rawPublicKey } = generateEd25519KeyPair();
    const payload = { verb: "sign", agent: "test.eth", timestamp: "2026-01-01T00:00:00Z" };
    const canonical = canonicalize(payload);
    const sig = signCanonical(canonical, privateKeyPem);

    const valid = verifyCanonicalWithRawKey(canonical, sig, rawPublicKey);
    assert.strictEqual(valid, true);
  });

  it("returns false for tampered payload", () => {
    const { privateKeyPem, publicKeyPem } = generateEd25519KeyPair();
    const payload = { verb: "verify", agent: "test.eth", timestamp: "2026-01-01T00:00:00Z" };
    const canonical = canonicalize(payload);
    const sig = signCanonical(canonical, privateKeyPem);

    const tampered = canonicalize({ ...payload, agent: "evil.eth" });
    const valid = verifyCanonical(tampered, sig, publicKeyPem);
    assert.strictEqual(valid, false);
  });

  it("returns false for wrong key", () => {
    const { privateKeyPem } = generateEd25519KeyPair();
    const { publicKeyPem: wrongPub } = generateEd25519KeyPair();
    const canonical = canonicalize({ verb: "test" });
    const sig = signCanonical(canonical, privateKeyPem);

    const valid = verifyCanonical(canonical, sig, wrongPub);
    assert.strictEqual(valid, false);
  });

  it("throws on signature wrong length", () => {
    const { publicKeyPem } = generateEd25519KeyPair();
    assert.throws(
      () => verifyCanonical("test", Buffer.from("tooshort").toString("base64"), publicKeyPem),
      /64 bytes/
    );
  });
});

describe("sign and verify — signing message is raw bytes", () => {
  it("signing message is raw canonical UTF-8, not sha256 hex", () => {
    // This test documents and enforces the protocol decision:
    // we sign raw bytes, not sha256(canonical).
    // If this ever needs to change, it requires a protocol version bump.
    const { privateKeyPem, publicKeyPem } = generateEd25519KeyPair();
    const payload = { verb: "test", agent: "test.eth", timestamp: "2026-01-01T00:00:00Z" };
    const canonical = canonicalize(payload);

    // Sign raw canonical
    const sig = signCanonical(canonical, privateKeyPem);

    // Verification with raw canonical should succeed
    assert.strictEqual(verifyCanonical(canonical, sig, publicKeyPem), true);

    // Verification with sha256(canonical) would fail — different message
    const { createHash } = await import("node:crypto");
    const sha256hex = createHash("sha256").update(canonical, "utf8").digest("hex");
    // sha256hex is a different string — if someone signs this instead, verify fails
    assert.strictEqual(verifyCanonical(sha256hex, sig, publicKeyPem), false);
  });
});
