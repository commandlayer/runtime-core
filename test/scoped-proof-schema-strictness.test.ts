import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { generateEd25519KeyPair } from "../src/crypto.js";
import {
  signExecutionScopedProof,
  verifyClasScopedProofs,
  type ClasExecutionReceipt,
} from "../src/scoped-proofs.js";

function receipt(): ClasExecutionReceipt {
  return {
    clas: "1.0",
    schema: "clas.execution.receipt.v1",
    receipt_id: "rcpt_strict_1",
    verb: "example",
    agent: {
      ens: "exampleagent.eth",
      erc8004: "eip155:1/erc8004/1#example",
      kid: "kid_1",
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

describe("strict CLAS proof schema boundary", () => {
  it("rejects legacy hash-bearing proof fields", () => {
    const key = generateEd25519KeyPair();
    const signed = signExecutionScopedProof(receipt(), {
      privateKeyPem: key.privateKeyPem,
      kid: "kid_1",
      signer: "exampleagent.eth",
    });
    const proof = signed.proofs?.[0] as unknown as Record<string, unknown>;
    proof.hash = { alg: "SHA-256", value: "a".repeat(64) };

    const result = verifyClasScopedProofs(signed, {
      publicKeysByKid: { kid_1: key.publicKeyPem },
    });
    assert.strictEqual(result.ok, false);
    assert.ok(result.proofs[0].errors.includes("ERR_UNEXPECTED_PROOF_FIELD:hash"));
  });

  it("rejects signer metadata nested inside signature", () => {
    const key = generateEd25519KeyPair();
    const signed = signExecutionScopedProof(receipt(), {
      privateKeyPem: key.privateKeyPem,
      kid: "kid_1",
      signer: "exampleagent.eth",
    });
    const signature = signed.proofs?.[0].signature as unknown as Record<string, unknown>;
    signature.signer = "legacy-signature-location.eth";

    const result = verifyClasScopedProofs(signed, {
      publicKeysByKid: { kid_1: key.publicKeyPem },
    });
    assert.strictEqual(result.ok, false);
    assert.ok(result.proofs[0].errors.includes("ERR_UNEXPECTED_SIGNATURE_FIELD:signer"));
  });

  it("rejects lowercase ed25519 alias in the strict CLAS verifier", () => {
    const key = generateEd25519KeyPair();
    const signed = signExecutionScopedProof(receipt(), {
      privateKeyPem: key.privateKeyPem,
      kid: "kid_1",
      signer: "exampleagent.eth",
    });
    (signed.proofs?.[0].signature as unknown as { alg: string }).alg = "ed25519";

    const result = verifyClasScopedProofs(signed, {
      publicKeysByKid: { kid_1: key.publicKeyPem },
    });
    assert.strictEqual(result.ok, false);
    assert.ok(result.proofs[0].errors.includes("ERR_UNSUPPORTED_SIGNATURE_ALG"));
  });
});
