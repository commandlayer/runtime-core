import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  CANONICAL_ID_SORTED_KEYS_V1,
  signReceiptEd25519Sha256,
  verifyReceiptEd25519Sha256,
} from "../src/compat.js";
import { generateEd25519KeyPair } from "../src/crypto.js";

describe("CANONICAL_ID_SORTED_KEYS_V1", () => {
  test("equals json.sorted_keys.v1", () => {
    assert.equal(CANONICAL_ID_SORTED_KEYS_V1, "json.sorted_keys.v1");
  });
});

describe("signReceiptEd25519Sha256 / verifyReceiptEd25519Sha256", () => {
  const kp = generateEd25519KeyPair();

  const baseReceipt = {
    verb: "test",
    version: "1.1.0",
    agent: "test.commandlayer.eth",
    timestamp: "2026-05-13T00:00:00.000Z",
    metadata: { session_id: "abc123" },
  };

  test("signs and verifies a receipt", () => {
    const signed = signReceiptEd25519Sha256(baseReceipt, {
      signer_id: "test.commandlayer.eth",
      kid: "testKid",
      privateKeyPem: kp.privateKeyPem,
    });

    assert.ok(signed.metadata?.proof, "should have metadata.proof");
    const proof = signed.metadata.proof;
    assert.equal(proof.alg, "ed25519");
    assert.equal(proof.kid, "testKid");
    assert.equal(proof.signer_id, "test.commandlayer.eth");
    assert.equal(proof.canonical, "json.sorted_keys.v1");
    assert.ok(proof.signature, "should have signature");
    assert.ok(proof.signature_b64, "should have signature_b64");
    assert.equal(proof.signature, proof.signature_b64, "signature and signature_b64 should match");
    assert.ok(proof.hash_sha256, "should have hash_sha256");

    const result = verifyReceiptEd25519Sha256(signed, {
      publicKeyPemOrDer: kp.publicKeyPem,
    });

    assert.ok(result.ok, `verify should succeed: ${result.reason}`);
    assert.ok(result.checks.signature_valid);
    assert.ok(result.checks.hash_matches);
  });

  test("verify fails with wrong public key", () => {
    const signed = signReceiptEd25519Sha256(baseReceipt, {
      signer_id: "test.commandlayer.eth",
      kid: "testKid",
      privateKeyPem: kp.privateKeyPem,
    });

    const wrongKp = generateEd25519KeyPair();
    const result = verifyReceiptEd25519Sha256(signed, {
      publicKeyPemOrDer: wrongKp.publicKeyPem,
    });

    assert.ok(!result.ok, "verify should fail with wrong key");
    assert.ok(!result.checks.signature_valid);
  });

  test("verify fails if receipt tampered after signing", () => {
    const signed = signReceiptEd25519Sha256(baseReceipt, {
      signer_id: "test.commandlayer.eth",
      kid: "testKid",
      privateKeyPem: kp.privateKeyPem,
    });

    const tampered = { ...signed, verb: "tampered" };
    const result = verifyReceiptEd25519Sha256(tampered, {
      publicKeyPemOrDer: kp.publicKeyPem,
    });

    assert.ok(!result.ok, "verify should fail for tampered receipt");
  });

  test("verify fails with missing proof", () => {
    const result = verifyReceiptEd25519Sha256(baseReceipt, {
      publicKeyPemOrDer: kp.publicKeyPem,
    });
    assert.ok(!result.ok);
    assert.match(result.reason ?? "", /Missing metadata\.proof/);
  });

  test("proof block excluded from signed payload — signing is idempotent", () => {
    const signed = signReceiptEd25519Sha256(baseReceipt, {
      signer_id: "test.commandlayer.eth",
      kid: "testKid",
      privateKeyPem: kp.privateKeyPem,
    });

    // Re-signing an already-signed receipt should produce the same signature
    const signed2 = signReceiptEd25519Sha256(signed, {
      signer_id: "test.commandlayer.eth",
      kid: "testKid",
      privateKeyPem: kp.privateKeyPem,
    });

    assert.equal(
      signed.metadata.proof.signature,
      signed2.metadata.proof.signature,
      "proof block must not be included in signed payload"
    );

    const r2 = verifyReceiptEd25519Sha256(signed2, { publicKeyPemOrDer: kp.publicKeyPem });
    assert.ok(r2.ok);
  });

  test("supports signature via signature_b64 field", () => {
    const signed = signReceiptEd25519Sha256(baseReceipt, {
      signer_id: "test.commandlayer.eth",
      kid: "testKid",
      privateKeyPem: kp.privateKeyPem,
    });

    // Simulate a legacy receipt that only has signature_b64
    const legacy = {
      ...signed,
      metadata: {
        ...signed.metadata,
        proof: { ...signed.metadata.proof, signature: undefined },
      },
    };

    const result = verifyReceiptEd25519Sha256(legacy as typeof signed, {
      publicKeyPemOrDer: kp.publicKeyPem,
    });
    assert.ok(result.ok, `should verify via signature_b64: ${result.reason}`);
  });
});
