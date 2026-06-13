import { createHash } from "node:crypto";
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { canonicalize } from "../src/canonicalize.js";
import { generateEd25519KeyPair, signCanonical } from "../src/crypto.js";
import {
  buildCoveredPayload,
  verifyScopedProofs,
  type CommandLayerReceipt,
  type CommandLayerScopedProof,
} from "../src/compat.js";

function makeReceipt(): CommandLayerReceipt {
  return {
    version: "clas.execution.receipt.v1",
    receipt_id: "rcpt_123",
    verb: "approve",
    agent: { id: "acme.approveagent.eth" },
    action: { input_hash: "a".repeat(64), output_hash: "b".repeat(64) },
    settlement: { rail: "x402", payment_ref: "pay_123" },
  };
}

function scopedProof(
  receipt: CommandLayerReceipt,
  proof: Pick<CommandLayerScopedProof, "type" | "covers">,
  privateKeyPem: string,
  kid: string,
  signer: string,
): CommandLayerScopedProof {
  const canonical = canonicalize(buildCoveredPayload(receipt, proof));
  return {
    ...proof,
    canonicalization: "json.sorted_keys.v1",
    hash: { alg: "SHA-256", value: createHash("sha256").update(canonical, "utf8").digest("hex") },
    signature: { alg: "Ed25519", value: signCanonical(canonical, privateKeyPem), kid, signer },
  };
}

function signReceiptWithProofs() {
  const receipt = makeReceipt();
  const executionKey = generateEd25519KeyPair();
  const settlementKey = generateEd25519KeyPair();
  const execution = scopedProof(
    receipt,
    { type: "execution", covers: ["receipt_id", "verb", "agent", "action"] },
    executionKey.privateKeyPem,
    "execution-kid",
    "acme.approveagent.eth",
  );
  const settlement = scopedProof(
    receipt,
    { type: "settlement", covers: ["receipt_id", "settlement"] },
    settlementKey.privateKeyPem,
    "settlement-kid",
    "x402:payer.example",
  );
  return { receipt: { ...receipt, proofs: [execution, settlement] }, executionKey, settlementKey };
}

describe("CLAS scoped proofs", () => {
  it("materializes covered payloads in the exact covers[] order before sorted-key canonicalization", () => {
    const receipt = makeReceipt();
    assert.deepStrictEqual(
      buildCoveredPayload(receipt, { type: "execution", covers: ["receipt_id", "verb", "agent", "action"] }),
      { receipt_id: "rcpt_123", verb: "approve", agent: { id: "acme.approveagent.eth" }, action: { input_hash: "a".repeat(64), output_hash: "b".repeat(64) } },
    );
    assert.deepStrictEqual(
      buildCoveredPayload(receipt, { type: "settlement", covers: ["receipt_id", "settlement"] }),
      { receipt_id: "rcpt_123", settlement: { rail: "x402", payment_ref: "pay_123" } },
    );
  });

  it("verifies an execution-only receipt when execution proof signs only receipt_id, verb, agent, action", () => {
    const base = makeReceipt();
    delete base.settlement;
    const key = generateEd25519KeyPair();
    const proof = scopedProof(base, { type: "execution", covers: ["receipt_id", "verb", "agent", "action"] }, key.privateKeyPem, "execution-kid", "acme.approveagent.eth");
    const result = verifyScopedProofs({ ...base, proofs: [proof] }, { publicKeysByKid: { "execution-kid": key.publicKeyPem } });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.proofs[0].signature_valid, true);
    assert.strictEqual(result.proofs[0].hash_matches, true);
  });

  it("verifies execution + settlement receipt with two scoped proofs", () => {
    const { receipt, executionKey, settlementKey } = signReceiptWithProofs();
    const result = verifyScopedProofs(receipt, { publicKeysByKid: { "execution-kid": executionKey.publicKeyPem, "settlement-kid": settlementKey.publicKeyPem } });
    assert.strictEqual(result.ok, true);
    assert.deepStrictEqual(result.proofs.map((proof) => proof.type), ["execution", "settlement"]);
  });

  it("tampering action.output_hash invalidates execution proof but not settlement proof", () => {
    const { receipt, executionKey, settlementKey } = signReceiptWithProofs();
    (receipt.action as Record<string, unknown>).output_hash = "c".repeat(64);
    const result = verifyScopedProofs(receipt, { publicKeysByKid: { "execution-kid": executionKey.publicKeyPem, "settlement-kid": settlementKey.publicKeyPem } });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.proofs[0].ok, false);
    assert.strictEqual(result.proofs[1].ok, true);
  });

  it("tampering settlement.payment_ref invalidates settlement proof but not execution proof", () => {
    const { receipt, executionKey, settlementKey } = signReceiptWithProofs();
    (receipt.settlement as Record<string, unknown>).payment_ref = "pay_tampered";
    const result = verifyScopedProofs(receipt, { publicKeysByKid: { "execution-kid": executionKey.publicKeyPem, "settlement-kid": settlementKey.publicKeyPem } });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.proofs[0].ok, true);
    assert.strictEqual(result.proofs[1].ok, false);
  });

  it("rejects execution proof that covers settlement", () => {
    const receipt = makeReceipt();
    assert.throws(() => buildCoveredPayload(receipt, { type: "execution", covers: ["receipt_id", "verb", "agent", "action", "settlement"] }), /ERR_INVALID_EXECUTION_COVERS/);
  });

  it("rejects settlement present without settlement proof", () => {
    const { receipt, executionKey } = signReceiptWithProofs();
    receipt.proofs = [receipt.proofs![0]];
    const result = verifyScopedProofs(receipt, { publicKeysByKid: { "execution-kid": executionKey.publicKeyPem } });
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors.includes("ERR_MISSING_SETTLEMENT_PROOF"));
  });

  it("rejects unknown proof type and malformed covers[]", () => {
    const receipt = makeReceipt();
    assert.throws(() => buildCoveredPayload(receipt, { type: "authorization", covers: ["receipt_id"] }), /ERR_UNSUPPORTED_PROOF_TYPE/);
    assert.throws(() => buildCoveredPayload(receipt, { type: "execution", covers: "receipt_id" as unknown as string[] }), /ERR_MALFORMED_COVERS/);
  });

  it("does not require raw settlement stealth address or raw transaction hash fields", () => {
    const { receipt, executionKey, settlementKey } = signReceiptWithProofs();
    assert.equal((receipt.settlement as Record<string, unknown>).stealth_address, undefined);
    assert.equal((receipt.settlement as Record<string, unknown>).tx_hash, undefined);
    const result = verifyScopedProofs(receipt, { publicKeysByKid: { "execution-kid": executionKey.publicKeyPem, "settlement-kid": settlementKey.publicKeyPem } });
    assert.strictEqual(result.ok, true);
  });
});
