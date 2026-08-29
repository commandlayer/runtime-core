import test from "node:test";
import assert from "node:assert/strict";
import {
  FACTORY_EXECUTION_RECEIPT_PROFILE,
  FACTORY_EXECUTION_PROOF_COVERS,
  buildFactoryExecutionPayload,
  generateEd25519KeyPair,
  signFactoryExecutionReceipt,
  verifyFactoryExecutionReceipt,
  type FactoryExecutionReceipt,
} from "../src/index.js";

function fixture(): FactoryExecutionReceipt {
  return {
    receipt_id: "rcpt_factory_1",
    profile: FACTORY_EXECUTION_RECEIPT_PROFILE,
    issued_at: "2026-08-29T15:30:00.000Z",
    service: {
      service_id: "researchagent",
      service_version: "0.1.0",
    },
    execution: {
      execution_id: "exec_1",
      request_fingerprint: "sha256:" + "a".repeat(64),
      input_hash: "sha256:" + "b".repeat(64),
      output_hash: "sha256:" + "c".repeat(64),
      started_at: "2026-08-29T15:29:58.000Z",
      completed_at: "2026-08-29T15:29:59.000Z",
      provider_steps: [],
      acceptance_checks: [],
    },
  };
}

test("factory receipt signs and verifies without ENS, ERC-8004 or settlement fields", () => {
  const keys = generateEd25519KeyPair();
  const signed = signFactoryExecutionReceipt(fixture(), {
    privateKeyPem: keys.privateKeyPem,
    kid: "factory-test-key",
    signer: "commandlayer:test-signer",
  });

  assert.deepEqual(signed.proof?.covers, [...FACTORY_EXECUTION_PROOF_COVERS]);
  assert.equal(signed.proof?.signer, "commandlayer:test-signer");
  assert.equal(Object.hasOwn(signed, "settlement"), false);
  assert.equal(Object.hasOwn(signed, "agent"), false);

  const result = verifyFactoryExecutionReceipt(signed, { publicKeyPemOrDer: keys.publicKeyPem });
  assert.equal(result.ok, true);
  assert.equal(result.status, "VERIFIED");
  assert.equal(result.signature_valid, true);
});

test("factory execution proof covers the complete service/execution envelope and excludes proof itself", () => {
  const receipt = fixture();
  assert.deepEqual(Object.keys(buildFactoryExecutionPayload(receipt)), [
    "receipt_id",
    "profile",
    "issued_at",
    "service",
    "execution",
  ]);
});

test("factory receipt verification rejects execution evidence tampering", () => {
  const keys = generateEd25519KeyPair();
  const signed = signFactoryExecutionReceipt(fixture(), {
    privateKeyPem: keys.privateKeyPem,
    kid: "factory-test-key",
    signer: "commandlayer:test-signer",
  });

  const tampered = structuredClone(signed);
  tampered.execution.output_hash = "sha256:" + "d".repeat(64);
  const result = verifyFactoryExecutionReceipt(tampered, { publicKeyPemOrDer: keys.publicKeyPem });
  assert.equal(result.ok, false);
  assert(result.errors.includes("ERR_SIGNATURE_INVALID"));
});

test("factory receipt verification supports registry-neutral key resolution by kid", () => {
  const keys = generateEd25519KeyPair();
  const signed = signFactoryExecutionReceipt(fixture(), {
    privateKeyPem: keys.privateKeyPem,
    kid: "kid-42",
    signer: "did:key:example",
  });
  const result = verifyFactoryExecutionReceipt(signed, {
    publicKeysByKid: { "kid-42": keys.publicKeyPem },
  });
  assert.equal(result.ok, true);
  assert.equal(result.signer, "did:key:example");
});

test("factory receipt verification rejects expanded proof coverage or extra proof fields", () => {
  const keys = generateEd25519KeyPair();
  const signed = signFactoryExecutionReceipt(fixture(), {
    privateKeyPem: keys.privateKeyPem,
    kid: "kid-42",
    signer: "commandlayer:test",
  });

  const expanded = structuredClone(signed);
  expanded.proof!.covers = [...expanded.proof!.covers, "settlement"];
  assert(verifyFactoryExecutionReceipt(expanded, { publicKeyPemOrDer: keys.publicKeyPem }).errors.includes("ERR_INVALID_EXECUTION_COVERS"));

  const extra = structuredClone(signed) as FactoryExecutionReceipt & { proof: Record<string, unknown> };
  (extra.proof as Record<string, unknown>).hash = "forbidden";
  assert(verifyFactoryExecutionReceipt(extra as FactoryExecutionReceipt, { publicKeyPemOrDer: keys.publicKeyPem }).errors.includes("ERR_UNEXPECTED_PROOF_FIELD:hash"));
});
