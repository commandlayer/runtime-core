import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { generateEd25519KeyPair } from "../src/crypto.js";
import {
  createScopedProof,
  signExecutionScopedProof,
  signSettlementScopedProof,
} from "../src/scoped-proofs.js";
import { verifyScopedProofs, type CommandLayerReceipt } from "../src/compat.js";

function executionReceipt(): CommandLayerReceipt {
  return {
    version: "clas.execution.receipt.v1",
    receipt_id: "rcpt_signing_1",
    verb: "example",
    agent: { id: "exampleagent.eth" },
    action: {
      input_hash: "a".repeat(64),
      output_hash: "b".repeat(64),
    },
  };
}

describe("runtime-core scoped proof signing", () => {
  it("chooses execution coverage inside runtime-core rather than from the caller", () => {
    const key = generateEd25519KeyPair();
    const receipt = executionReceipt();
    const proof = createScopedProof(receipt, "execution", {
      privateKeyPem: key.privateKeyPem,
      kid: "exec-kid",
      signer: "exampleagent.eth",
    });

    assert.deepStrictEqual(proof.covers, ["receipt_id", "verb", "agent", "action"]);
    assert.strictEqual(proof.type, "execution");
    assert.strictEqual(proof.signature.kid, "exec-kid");
    assert.strictEqual(proof.signature.signer, "exampleagent.eth");
  });

  it("signs an execution proof that verifies with the existing scoped verifier", () => {
    const key = generateEd25519KeyPair();
    const base = executionReceipt();
    const signed = signExecutionScopedProof(base, {
      privateKeyPem: key.privateKeyPem,
      kid: "exec-kid",
      signer: "exampleagent.eth",
    });

    assert.strictEqual(base.proofs, undefined, "input receipt must not be mutated");
    const result = verifyScopedProofs(signed, {
      publicKeysByKid: { "exec-kid": key.publicKeyPem },
    });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.proofs.length, 1);
    assert.strictEqual(result.proofs[0].type, "execution");
  });

  it("keeps execution and settlement proofs independently scoped", () => {
    const executionKey = generateEd25519KeyPair();
    const settlementKey = generateEd25519KeyPair();
    const base: CommandLayerReceipt = {
      ...executionReceipt(),
      settlement: { rail: "test-rail", payment_ref: "pay_1" },
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

    const valid = verifyScopedProofs(signed, {
      publicKeysByKid: {
        "exec-kid": executionKey.publicKeyPem,
        "settlement-kid": settlementKey.publicKeyPem,
      },
    });
    assert.strictEqual(valid.ok, true);

    (signed.action as Record<string, unknown>).output_hash = "c".repeat(64);
    const tampered = verifyScopedProofs(signed, {
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
});
