import test from "node:test";
import assert from "node:assert/strict";

import {
  FACTORY_EXECUTION_RECEIPT_PROFILE,
  generateEd25519KeyPair,
  signFactoryExecutionReceipt,
  verifyFactoryExecutionReceipt,
  type FactoryExecutionReceipt,
} from "../src/index.js";

const H = `sha256:${"a".repeat(64)}`;
const H2 = `sha256:${"b".repeat(64)}`;
const H3 = `sha256:${"c".repeat(64)}`;
const H4 = `sha256:${"d".repeat(64)}`;

function receipt(): FactoryExecutionReceipt {
  return {
    receipt_id: "rcpt_test_1",
    profile: FACTORY_EXECUTION_RECEIPT_PROFILE,
    issued_at: "2026-08-29T23:00:02.000Z",
    service: {
      service_id: "researchagent",
      service_version: "0.1.0",
    },
    execution: {
      execution_id: "exec_test_1",
      service_id: "researchagent",
      service_version: "0.1.0",
      request_fingerprint: H,
      workflow_hash: H2,
      input_hash: H3,
      output_hash: H4,
      started_at: "2026-08-29T23:00:00.000Z",
      completed_at: "2026-08-29T23:00:01.000Z",
      provider_steps: [
        {
          step_id: "retrieve",
          kind: "search",
          provider: "tavily",
          started_at: "2026-08-29T23:00:00.000Z",
          completed_at: "2026-08-29T23:00:00.500Z",
          result_hash: H3,
        },
      ],
      acceptance_checks: [
        {
          name: "contract",
          status: "pass",
          assertion: "result matches declared contract",
          observed: { ok: true },
        },
      ],
      observed_state: null,
    },
  };
}

test("factory execution receipt signs and verifies with direct Ed25519 key", async () => {
  const keys = generateEd25519KeyPair();
  const signed = signFactoryExecutionReceipt(receipt(), {
    privateKeyPem: keys.privateKeyPem,
    kid: "runtime-2026-08",
    signerId: "runtime.commandlayer.eth",
  });

  assert.equal(signed.profile, FACTORY_EXECUTION_RECEIPT_PROFILE);
  assert.equal(signed.proof.alg, "Ed25519");
  assert.equal(signed.proof.signer_id, "runtime.commandlayer.eth");

  const verified = await verifyFactoryExecutionReceipt(signed, {
    publicKeyPem: keys.publicKeyPem,
    expectedKid: "runtime-2026-08",
    expectedSigner: "runtime.commandlayer.eth",
  });
  assert.equal(verified.valid, true, verified.reason);
  assert.equal(verified.checks.signatureValid, true);
});

test("factory execution receipt supports asynchronous production key resolution", async () => {
  const keys = generateEd25519KeyPair();
  const signed = signFactoryExecutionReceipt(receipt(), {
    privateKeyPem: keys.privateKeyPem,
    kid: "kid-resolved",
    signerId: "signer.commandlayer.eth",
  });

  let resolverCalls = 0;
  const verified = await verifyFactoryExecutionReceipt(signed, {
    resolveKey: async ({ kid, signerId, alg }) => {
      resolverCalls += 1;
      assert.equal(kid, "kid-resolved");
      assert.equal(signerId, "signer.commandlayer.eth");
      assert.equal(alg, "Ed25519");
      return {
        rawPublicKey: keys.rawPublicKey,
        kid,
        signerId,
      };
    },
  });

  assert.equal(resolverCalls, 1);
  assert.equal(verified.valid, true, verified.reason);
});

test("tampering execution evidence after signing invalidates the receipt", async () => {
  const keys = generateEd25519KeyPair();
  const signed = signFactoryExecutionReceipt(receipt(), {
    privateKeyPem: keys.privateKeyPem,
    kid: "kid-1",
    signerId: "runtime.commandlayer.eth",
  });

  const tampered = structuredClone(signed);
  tampered.execution.output_hash = H;
  const verified = await verifyFactoryExecutionReceipt(tampered, {
    publicKeyPem: keys.publicKeyPem,
  });
  assert.equal(verified.valid, false);
  assert.equal(verified.checks.signatureValid, false);
});

test("service identity and workflow hash are inside the signed execution evidence", async () => {
  const keys = generateEd25519KeyPair();
  const signed = signFactoryExecutionReceipt(receipt(), {
    privateKeyPem: keys.privateKeyPem,
    kid: "kid-2",
    signerId: "runtime.commandlayer.eth",
  });

  const workflowTamper = structuredClone(signed);
  workflowTamper.execution.workflow_hash = H3;
  assert.equal((await verifyFactoryExecutionReceipt(workflowTamper, { publicKeyPem: keys.publicKeyPem })).valid, false);

  const serviceTamper = structuredClone(signed);
  serviceTamper.service.service_id = "verifyagent";
  const verified = await verifyFactoryExecutionReceipt(serviceTamper, { publicKeyPem: keys.publicKeyPem });
  assert.equal(verified.valid, false);
  assert.equal(verified.checks.serviceBindingValid, false);
});

test("payment and settlement proof fields are rejected from factory execution receipts", () => {
  const keys = generateEd25519KeyPair();
  const invalid = receipt() as FactoryExecutionReceipt & { payment_id?: string };
  invalid.payment_id = "pay_123";
  assert.throws(
    () => signFactoryExecutionReceipt(invalid, {
      privateKeyPem: keys.privateKeyPem,
      kid: "kid-3",
      signerId: "runtime.commandlayer.eth",
    }),
    /must not contain payment proof fields/,
  );
});

test("verification fails closed when no public key can be resolved", async () => {
  const keys = generateEd25519KeyPair();
  const signed = signFactoryExecutionReceipt(receipt(), {
    privateKeyPem: keys.privateKeyPem,
    kid: "missing-key",
    signerId: "runtime.commandlayer.eth",
  });
  const result = await verifyFactoryExecutionReceipt(signed, { resolveKey: async () => null });
  assert.equal(result.valid, false);
  assert.match(result.reason || "", /No verification key available/);
});
