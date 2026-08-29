import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { generateEd25519KeyPair } from "../src/crypto.js";
import {
  createScopedProof,
  signExecutionScopedProof,
  signSettlementScopedProof,
  verifyClasScopedProofs,
  type ClasExecutionReceipt,
} from "../src/scoped-proofs.js";

function executionReceipt(): ClasExecutionReceipt {
  return {
    clas: "1.0",
    schema: "clas.execution.receipt.v1",
    receipt_id: "rcpt_signing_1",
    verb: "example",
    agent: {
      ens: "exampleagent.eth",
      erc8004: "eip155:1/erc8004/1#example",
      kid: "exec-kid",
      public_key_source: "ens_txt",
    },
    action: {
      input_hash: `sha256:${"a".repeat(64)}`,
      output_hash: `sha256:${"b".repeat(64)}`,
      started_at: "2026-08-29T00:00:00.000Z",
      completed_at: "2026-08-29T00:00:01.000Z",
    },
  };
}

describe("runtime-core strict CLAS scoped proof signing", () => {
  it("emits the canonical CLAS proof shape with top-level signer and no hash", () => {
    const key = generateEd25519KeyPair();
    const receipt = executionReceipt();
    const proof = createScopedProof(receipt, "execution", {
      privateKeyPem: key.privateKeyPem,
      kid: "exec-kid",
      signer: "exampleagent.eth",
    });

    assert.deepStrictEqual(proof.covers, ["receipt_id", "verb", "agent", "action"]);
    assert.strictEqual(proof.type, "execution");
    assert.strictEqual(proof.signer, "exampleagent.eth");
    assert.strictEqual(proof.signature.kid, "exec-kid");
    assert.strictEqual("hash" in proof, false);
    assert.strictEqual("signer" in proof.signature, false);
  });

  it("signs an execution proof that verifies with the strict CLAS verifier", () => {
    const key = generateEd25519KeyPair();
    const base = executionReceipt();
    const signed = signExecutionScopedProof(base, {
      privateKeyPem: key.privateKeyPem,
      kid: "exec-kid",
      signer: "exampleagent.eth",
    });

    assert.strictEqual(base.proofs, undefined, "input receipt must not be mutated");
    const result = verifyClasScopedProofs(signed, {
      publicKeysByKid: { "exec-kid": key.publicKeyPem },
    });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.proofs.length, 1);
    assert.strictEqual(result.proofs[0].type, "execution");
    assert.strictEqual(result.proofs[0].signer, "exampleagent.eth");
  });

  it("keeps execution and settlement proofs independently scoped", () => {
    const executionKey = generateEd25519KeyPair();
    const settlementKey = generateEd25519KeyPair();
    const base: ClasExecutionReceipt = {
      ...executionReceipt(),
      settlement: {
        rail: "x402",
        privacy: "stealth_address",
        status: "settled",
        payment_ref: "pay_1",
        payee_commitment: `sha256:${"c".repeat(64)}`,
        verification: { mode: "selective_disclosure", viewer_required: true },
      },
    };

    const withExecution = signExecutionScopedProof(base, {
      privateKeyPem: executionKey.privateKeyPem,
      kid: "exec-kid",
      signer: "exampleagent.eth",
    });
    const signed = signSettlementScopedProof(withExecution, {
      privateKeyPem: settlementKey.privateKeyPem,
      kid: "settlement-kid",
      signer: "settlement:test",
    });

    assert.deepStrictEqual(signed.proofs?.map((proof) => proof.covers), [
      ["receipt_id", "verb", "agent", "action"],
      ["receipt_id", "settlement"],
    ]);

    const valid = verifyClasScopedProofs(signed, {
      publicKeysByKid: {
        "exec-kid": executionKey.publicKeyPem,
        "settlement-kid": settlementKey.publicKeyPem,
      },
    });
    assert.strictEqual(valid.ok, true);

    (signed.action as Record<string, unknown>).output_hash = `sha256:${"d".repeat(64)}`;
    const tampered = verifyClasScopedProofs(signed, {
      publicKeysByKid: {
        "exec-kid": executionKey.publicKeyPem,
        "settlement-kid": settlementKey.publicKeyPem,
      },
    });
    assert.strictEqual(tampered.ok, false);
    assert.strictEqual(tampered.proofs[0].ok, false);
    assert.strictEqual(tampered.proofs[1].ok, true);
  });

  it("refuses to sign settlement proof when settlement is absent", () => {
    const key = generateEd25519KeyPair();
    assert.throws(
      () => signSettlementScopedProof(executionReceipt(), {
        privateKeyPem: key.privateKeyPem,
        kid: "settlement-kid",
        signer: "settlement:test",
      }),
      /ERR_MISSING_COVERED_FIELD:settlement/,
    );
  });

  it("requires signer identity metadata at signing time", () => {
    const key = generateEd25519KeyPair();
    assert.throws(
      () => createScopedProof(executionReceipt(), "execution", {
        privateKeyPem: key.privateKeyPem,
        kid: "exec-kid",
        signer: "",
      }),
      /signer is required/,
    );
  });

  it("rejects a settlement proof when no settlement object exists", () => {
    const key = generateEd25519KeyPair();
    const receipt = executionReceipt();
    const executionSigned = signExecutionScopedProof(receipt, {
      privateKeyPem: key.privateKeyPem,
      kid: "exec-kid",
      signer: "exampleagent.eth",
    });
    executionSigned.proofs = [
      ...(executionSigned.proofs ?? []),
      {
        type: "settlement",
        covers: ["receipt_id", "settlement"],
        signer: "settlement:test",
        canonicalization: "json.sorted_keys.v1",
        signature: { alg: "Ed25519", kid: "settlement-kid", value: "x" },
      },
    ];

    const result = verifyClasScopedProofs(executionSigned, {
      publicKeysByKid: { "exec-kid": key.publicKeyPem, "settlement-kid": key.publicKeyPem },
    });
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors.includes("ERR_UNEXPECTED_SETTLEMENT_PROOF"));
  });
});
