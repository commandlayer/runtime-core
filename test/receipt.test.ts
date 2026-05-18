/**
 * Receipt tests — runtime-core
 *
 * Full round-trip: signReceipt → verifyReceipt
 * Tests proof field names, signer matching, and tamper detection.
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { generateEd25519KeyPair } from "../src/crypto.js";
import { signReceipt, verifyReceipt, isSignedLayeredReceipt, type ReceiptPayload } from "../src/receipt.js";

const makePayload = (): ReceiptPayload => ({
  verb: "verify",
  version: "1.1.0",
  agent: "runtime.commandlayer.eth",
  timestamp: new Date().toISOString(),
  payload: { input: "test-value" },
});

describe("signReceipt", () => {
  it("produces a SignedLayeredReceipt with correct proof fields", () => {
    const { privateKeyPem } = generateEd25519KeyPair();
    const receipt = signReceipt(makePayload(), {
      privateKeyPem,
      kid: "vC4WbcNoq2znSCiQ",
      signerEns: "runtime.commandlayer.eth",
    });

    assert.ok(receipt.receipt);
    assert.ok(receipt.signature?.proof);

    const proof = receipt.signature.proof;
    // Field names must match protocol spec
    assert.strictEqual(proof.alg, "Ed25519");          // not signature_alg
    assert.strictEqual(proof.kid, "vC4WbcNoq2znSCiQ"); // not key_id
    assert.strictEqual(proof.signer_id, "runtime.commandlayer.eth"); // not signer
    assert.strictEqual(proof.canonical, "json.sorted_keys.v1");

    // Signature is standard base64, 64 bytes
    const sigBytes = Buffer.from(proof.signature, "base64");
    assert.strictEqual(sigBytes.length, 64);
  });

  it("preserves version field in signed receipt", () => {
    const { privateKeyPem } = generateEd25519KeyPair();
    const payload = makePayload();
    payload.version = "1.1.0";
    const receipt = signReceipt(payload, {
      privateKeyPem,
      kid: "kid1",
      signerEns: "test.eth",
    });
    assert.strictEqual(receipt.receipt.version, "1.1.0");
  });

  it("throws if verb is missing", () => {
    const { privateKeyPem } = generateEd25519KeyPair();
    assert.throws(
      () => signReceipt(
        { version: "1.1.0", agent: "test.eth", timestamp: "2026-01-01T00:00:00Z", verb: "" } as ReceiptPayload,
        { privateKeyPem, kid: "kid1", signerEns: "test.eth" }
      ),
      /verb/
    );
  });

  it("throws if version is missing", () => {
    const { privateKeyPem } = generateEd25519KeyPair();
    assert.throws(
      () => signReceipt(
        { verb: "test", agent: "test.eth", timestamp: "2026-01-01T00:00:00Z", version: "" } as ReceiptPayload,
        { privateKeyPem, kid: "kid1", signerEns: "test.eth" }
      ),
      /version/
    );
  });

  it("throws if agent is missing", () => {
    const { privateKeyPem } = generateEd25519KeyPair();
    assert.throws(
      () => signReceipt(
        { verb: "test", version: "1.1.0", timestamp: "2026-01-01T00:00:00Z", agent: "" } as ReceiptPayload,
        { privateKeyPem, kid: "kid1", signerEns: "test.eth" }
      ),
      /agent/
    );
  });

  it("throws if timestamp is missing", () => {
    const { privateKeyPem } = generateEd25519KeyPair();
    assert.throws(
      () => signReceipt(
        { verb: "test", version: "1.1.0", agent: "test.eth", timestamp: "" } as ReceiptPayload,
        { privateKeyPem, kid: "kid1", signerEns: "test.eth" }
      ),
      /timestamp/
    );
  });
});

describe("verifyReceipt — full round trip", () => {
  it("returns valid: true for a correctly signed receipt", () => {
    const { privateKeyPem, rawPublicKey } = generateEd25519KeyPair();
    const signed = signReceipt(makePayload(), {
      privateKeyPem,
      kid: "vC4WbcNoq2znSCiQ",
      signerEns: "runtime.commandlayer.eth",
    });

    const result = verifyReceipt(signed, {
      rawPublicKey,
      expectedSigner: "runtime.commandlayer.eth",
      expectedKid: "vC4WbcNoq2znSCiQ",
    });

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.checks.signatureValid, true);
    assert.strictEqual(result.checks.signerMatched, true);
    assert.strictEqual(result.checks.kidMatched, true);
    assert.strictEqual(result.checks.algValid, true);
  });

  it("returns valid: false when payload is tampered", () => {
    const { privateKeyPem, rawPublicKey } = generateEd25519KeyPair();
    const signed = signReceipt(makePayload(), {
      privateKeyPem, kid: "kid1", signerEns: "test.eth",
    });

    // Tamper with the receipt payload after signing
    signed.receipt.payload = { input: "tampered" };

    const result = verifyReceipt(signed, { rawPublicKey });
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.checks.signatureValid, false);
  });

  it("returns valid: false when signer doesn't match expectedSigner", () => {
    const { privateKeyPem, rawPublicKey } = generateEd25519KeyPair();
    const signed = signReceipt(makePayload(), {
      privateKeyPem, kid: "kid1", signerEns: "alice.eth",
    });

    const result = verifyReceipt(signed, {
      rawPublicKey,
      expectedSigner: "bob.eth", // different from alice.eth
    });

    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.checks.signerMatched, false);
    // signerMatched MUST be part of validity — this tests the critical bug from audit #2
  });

  it("returns valid: false for wrong public key", () => {
    const { privateKeyPem } = generateEd25519KeyPair();
    const { rawPublicKey: wrongKey } = generateEd25519KeyPair();
    const signed = signReceipt(makePayload(), {
      privateKeyPem, kid: "kid1", signerEns: "test.eth",
    });

    const result = verifyReceipt(signed, { rawPublicKey: wrongKey });
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.checks.signatureValid, false);
  });



  it("accepts legacy lowercase ed25519 for compatibility", () => {
    const { privateKeyPem, rawPublicKey } = generateEd25519KeyPair();
    const signed = signReceipt(makePayload(), {
      privateKeyPem, kid: "kid1", signerEns: "test.eth",
    });
    (signed.signature.proof as Record<string, unknown>).alg = "ed25519";

    const result = verifyReceipt(signed, { rawPublicKey });
    assert.strictEqual(result.valid, true);
  });

  it("rejects unknown algorithm", () => {
    const { privateKeyPem, rawPublicKey } = generateEd25519KeyPair();
    const signed = signReceipt(makePayload(), {
      privateKeyPem, kid: "kid1", signerEns: "test.eth",
    });
    // Force wrong algorithm via unknown cast through Record
    (signed.signature.proof as Record<string, unknown>).alg = "rsa-pkcs1v15";

    const result = verifyReceipt(signed, { rawPublicKey });
    assert.strictEqual(result.valid, false);
    assert.ok(result.reason?.includes("Unsupported algorithm"));
  });

  it("throws if no public key provided", () => {
    const { privateKeyPem } = generateEd25519KeyPair();
    const signed = signReceipt(makePayload(), {
      privateKeyPem, kid: "kid1", signerEns: "test.eth",
    });
    assert.throws(() => verifyReceipt(signed, {}), /rawPublicKey or publicKeyPem/);
  });
});

describe("isSignedLayeredReceipt", () => {
  it("returns true for valid receipt", () => {
    const { privateKeyPem } = generateEd25519KeyPair();
    const signed = signReceipt(makePayload(), {
      privateKeyPem, kid: "kid1", signerEns: "test.eth",
    });
    assert.strictEqual(isSignedLayeredReceipt(signed), true);
  });

  it("returns false for flat/legacy receipt", () => {
    assert.strictEqual(isSignedLayeredReceipt({ proof: { signature: "abc" } }), false);
    assert.strictEqual(isSignedLayeredReceipt(null), false);
    assert.strictEqual(isSignedLayeredReceipt("string"), false);
  });

  it("returns false when signature is empty string", () => {
    const obj = {
      receipt: { verb: "test", version: "1.1.0", agent: "x", timestamp: "t" },
      signature: { proof: { alg: "Ed25519", signature: "", signer_id: "x", kid: "k", canonical: "json.sorted_keys.v1" } },
    };
    assert.strictEqual(isSignedLayeredReceipt(obj), false);
  });
});
