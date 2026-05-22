import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  signCommandLayerReceipt,
  verifyCommandLayerReceipt,
  isSignedCommandLayerReceipt,
  isMultiSignature,
} from "../src/compat.js";
import { generateEd25519KeyPair } from "../src/crypto.js";

describe("canonical CLAS proof envelope", () => {
  const kp = generateEd25519KeyPair();
  const baseReceipt = {
    verb: "test",
    version: "1.1.0",
    agent: "test.commandlayer.eth",
    timestamp: "2026-05-13T00:00:00.000Z",
    metadata: { session_id: "abc123" },
  };

  test("signs and verifies with canonical metadata.proof envelope", () => {
    const signed = signCommandLayerReceipt(baseReceipt, { privateKeyPem: kp.privateKeyPem, kid: "testKid" });
    const proof = signed.metadata!.proof!;
    assert.equal(proof.canonicalization, "json.sorted_keys.v1");
    assert.equal(proof.hash.alg, "SHA-256");
    assert.ok(proof.hash.value);
    assert.equal(proof.signature.alg, "Ed25519");
    assert.ok(proof.signature.value);
    assert.equal(proof.signature.kid, "testKid");

    const result = verifyCommandLayerReceipt(signed, { publicKeyPemOrDer: kp.publicKeyPem });
    assert.deepEqual(result.status, "VERIFIED");
    assert.deepEqual(result.checks, { schema: true, canonical_hash: true, signature: true, signer: true });
    assert.deepEqual(result.errors, []);
    assert.equal(isSignedCommandLayerReceipt(signed), true);
  });



  test("verifies canonical Ed25519 algorithm without caller normalization", () => {
    const signed = signCommandLayerReceipt(baseReceipt, { privateKeyPem: kp.privateKeyPem, kid: "testKid" });
    const proof = signed.metadata!.proof!;

    const canonical = verifyCommandLayerReceipt(
      { ...signed, metadata: { ...signed.metadata!, proof: { ...proof, signature: { ...proof.signature, alg: "Ed25519" } } } },
      { publicKeyPemOrDer: kp.publicKeyPem }
    );
    assert.equal(canonical.ok, true);

    const legacy = verifyCommandLayerReceipt(
      { ...signed, metadata: { ...signed.metadata!, proof: { ...proof, signature: { ...proof.signature, alg: "ed25519" } } } },
      { publicKeyPemOrDer: kp.publicKeyPem }
    );
    assert.equal(legacy.ok, true);
  });

  test("fails on unsupported signature algorithms", () => {
    const signed = signCommandLayerReceipt(baseReceipt, { privateKeyPem: kp.privateKeyPem, kid: "testKid" });
    const proof = signed.metadata!.proof!;

    const bad = verifyCommandLayerReceipt(
      { ...signed, metadata: { ...signed.metadata!, proof: { ...proof, signature: { ...proof.signature, alg: "rsa" as never } } } },
      { publicKeyPemOrDer: kp.publicKeyPem }
    );

    assert.equal(bad.status, "INVALID");
    assert.ok(bad.errors.includes("ERR_UNSUPPORTED_SIGNATURE_ALG"));
  });

  test("requires signature.kid to be a non-empty string", () => {
    const signed = signCommandLayerReceipt(baseReceipt, { privateKeyPem: kp.privateKeyPem, kid: "testKid" });
    const p = signed.metadata!.proof!;
    const missingKid = verifyCommandLayerReceipt(
      { ...signed, metadata: { ...signed.metadata!, proof: { ...p, signature: { ...p.signature, kid: "" } } } },
      { publicKeyPemOrDer: kp.publicKeyPem }
    );
    assert.equal(missingKid.status, "INVALID");
    assert.equal(missingKid.checks.schema, false);
    assert.ok(missingKid.errors.includes("ERR_MISSING_SIGNATURE_KID"));
  });

  test("returns INVALID and canonical_hash=false on invalid hash", () => {
    const signed = signCommandLayerReceipt(baseReceipt, { privateKeyPem: kp.privateKeyPem, kid: "testKid" });
    const bad = verifyCommandLayerReceipt(
      { ...signed, metadata: { ...signed.metadata!, proof: { ...signed.metadata!.proof!, hash: { ...signed.metadata!.proof!.hash, value: "00" } } } },
      { publicKeyPemOrDer: kp.publicKeyPem }
    );
    assert.equal(bad.status, "INVALID");
    assert.equal(bad.checks.canonical_hash, false);
    assert.ok(bad.errors.includes("ERR_HASH_MISMATCH"));
  });

  test("returns INVALID and signature=false on invalid signature", () => {
    const signed = signCommandLayerReceipt(baseReceipt, { privateKeyPem: kp.privateKeyPem, kid: "testKid" });
    const bad = verifyCommandLayerReceipt(
      { ...signed, metadata: { ...signed.metadata!, proof: { ...signed.metadata!.proof!, signature: { ...signed.metadata!.proof!.signature, value: Buffer.alloc(64).toString("base64") } } } },
      { publicKeyPemOrDer: kp.publicKeyPem }
    );
    assert.equal(bad.status, "INVALID");
    assert.equal(bad.checks.signature, false);
    assert.ok(bad.errors.includes("ERR_SIGNATURE_INVALID"));
  });

  test("validates ENS-compatible signer constraints when ensRecord is supplied", () => {
    const runtimeEnsFixture = {
      signer: "runtime.commandlayer.eth",
      kid: "vC4WbcNoq2znSCiQ",
      canonical: "json.sorted_keys.v1",
    };
    const signed = signCommandLayerReceipt({ ...baseReceipt, agent: "runtime.commandlayer.eth" }, { privateKeyPem: kp.privateKeyPem, kid: "vC4WbcNoq2znSCiQ" });
    const ok = verifyCommandLayerReceipt(signed, { publicKeyPemOrDer: kp.publicKeyPem, ensRecord: runtimeEnsFixture });
    assert.equal(ok.ok, true);
    assert.equal(ok.checks.signer, true);
  });

  test("accepts multi-signature array shape and signed receipt guard", () => {
    const signed = signCommandLayerReceipt(baseReceipt, { privateKeyPem: kp.privateKeyPem, kid: "testKid" });
    const sig = signed.metadata!.proof!.signature;
    const multiSig = [
      { ...sig, role: "agent" as const },
      { ...sig, role: "runtime" as const },
    ];
    const multi = { ...signed, metadata: { ...signed.metadata!, proof: { ...signed.metadata!.proof!, signature: multiSig } } };
    assert.equal(isMultiSignature(multiSig), true);
    assert.equal(isSignedCommandLayerReceipt(multi), true);
  });

  test("multi-signature verify path does not throw and verifies selected signature", () => {
    const signed = signCommandLayerReceipt(baseReceipt, { privateKeyPem: kp.privateKeyPem, kid: "testKid" });
    const sig = signed.metadata!.proof!.signature;
    const multi = {
      ...signed,
      metadata: {
        ...signed.metadata!,
        proof: {
          ...signed.metadata!.proof!,
          signature: [
            { ...sig, role: "user" as const },
            { ...sig, role: "runtime" as const },
          ],
        },
      },
    };
    const result = verifyCommandLayerReceipt(multi, { publicKeyPemOrDer: kp.publicKeyPem });
    assert.equal(result.status, "VERIFIED");
  });

  test("metadata.trace is ignored safely", () => {
    const withTrace = {
      ...baseReceipt,
      metadata: { ...baseReceipt.metadata, trace: [{ step: "signed" }] },
    };
    const signed = signCommandLayerReceipt(withTrace, { privateKeyPem: kp.privateKeyPem, kid: "testKid" });
    const result = verifyCommandLayerReceipt(signed, { publicKeyPemOrDer: kp.publicKeyPem });
    assert.equal(result.status, "VERIFIED");
  });

  test("malformed signature arrays return INVALID result without throwing", () => {
    const signed = signCommandLayerReceipt(baseReceipt, { privateKeyPem: kp.privateKeyPem, kid: "testKid" });
    const malformed = {
      ...signed,
      metadata: {
        ...signed.metadata!,
        proof: {
          ...signed.metadata!.proof!,
          signature: [{ alg: "Ed25519", value: "abc", kid: "kid-without-role" }],
        },
      },
    };
    const result = verifyCommandLayerReceipt(malformed, { publicKeyPemOrDer: kp.publicKeyPem });
    assert.equal(result.status, "INVALID");
    assert.ok(result.errors.includes("ERR_MALFORMED_SIGNATURE_ARRAY"));
  });

  test("erc8211 composable canonicalization is recognized, Merkle authorization verification deferred", () => {
    const signed = signCommandLayerReceipt(baseReceipt, { privateKeyPem: kp.privateKeyPem, kid: "testKid" });
    const recognized = verifyCommandLayerReceipt(
      { ...signed, metadata: { ...signed.metadata!, proof: { ...signed.metadata!.proof!, canonicalization: "erc8211.composable.v1" } } },
      { publicKeyPemOrDer: kp.publicKeyPem }
    );
    assert.equal(recognized.status, "INVALID");
    assert.ok(recognized.errors.includes("ERR_MERKLE_AUTHORIZATION_DEFERRED"));
    assert.ok(!recognized.errors.includes("ERR_UNSUPPORTED_CANONICALIZATION"));

    const unsupported = verifyCommandLayerReceipt(
      { ...signed, metadata: { ...signed.metadata!, proof: { ...signed.metadata!.proof!, canonicalization: "random.unsupported.v1" } } },
      { publicKeyPemOrDer: kp.publicKeyPem }
    );
    assert.ok(unsupported.errors.includes("ERR_UNSUPPORTED_CANONICALIZATION"));
  });
});
