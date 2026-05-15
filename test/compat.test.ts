import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  signCommandLayerReceipt,
  verifyCommandLayerReceipt,
  isSignedCommandLayerReceipt,
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
    assert.equal(proof.hash.alg, "sha256");
    assert.ok(proof.hash.value);
    assert.equal(proof.signature.alg, "ed25519");
    assert.ok(proof.signature.value);
    assert.equal(proof.signature.kid, "testKid");

    const result = verifyCommandLayerReceipt(signed, { publicKeyPemOrDer: kp.publicKeyPem });
    assert.ok(result.ok, result.reason);
    assert.equal(isSignedCommandLayerReceipt(signed), true);
  });

  test("rejects required canonical fields when missing", () => {
    const signed = signCommandLayerReceipt(baseReceipt, { privateKeyPem: kp.privateKeyPem, kid: "testKid" });
    const p = signed.metadata!.proof!;
    assert.equal(verifyCommandLayerReceipt({ ...signed, metadata: { ...signed.metadata!, proof: { ...p, hash: { ...p.hash, alg: "" as never } } } }, { publicKeyPemOrDer: kp.publicKeyPem }).ok, false);
    assert.equal(verifyCommandLayerReceipt({ ...signed, metadata: { ...signed.metadata!, proof: { ...p, hash: { ...p.hash, value: "" } } } }, { publicKeyPemOrDer: kp.publicKeyPem }).ok, false);
    assert.equal(verifyCommandLayerReceipt({ ...signed, metadata: { ...signed.metadata!, proof: { ...p, signature: { ...p.signature, alg: "" as never } } } }, { publicKeyPemOrDer: kp.publicKeyPem }).ok, false);
    assert.equal(verifyCommandLayerReceipt({ ...signed, metadata: { ...signed.metadata!, proof: { ...p, signature: { ...p.signature, value: "" } } } }, { publicKeyPemOrDer: kp.publicKeyPem }).ok, false);
    assert.equal(verifyCommandLayerReceipt({ ...signed, metadata: { ...signed.metadata!, proof: { ...p, signature: { ...p.signature, kid: "" } } } }, { publicKeyPemOrDer: kp.publicKeyPem }).ok, false);
  });

  test("validates ENS-compatible signer constraints when ensRecord is supplied", () => {
    const runtimeEnsFixture = {
      signer: "runtime.commandlayer.eth",
      kid: "vC4WbcNoq2znSCiQ",
      canonical: "json.sorted_keys.v1",
    };

    const signed = signCommandLayerReceipt(
      { ...baseReceipt, agent: "runtime.commandlayer.eth" },
      { privateKeyPem: kp.privateKeyPem, kid: "vC4WbcNoq2znSCiQ" }
    );

    const ok = verifyCommandLayerReceipt(signed, {
      publicKeyPemOrDer: kp.publicKeyPem,
      ensRecord: runtimeEnsFixture,
    });
    assert.equal(ok.ok, true);

    const badKid = verifyCommandLayerReceipt(
      { ...signed, metadata: { ...signed.metadata!, proof: { ...signed.metadata!.proof!, signature: { ...signed.metadata!.proof!.signature, kid: "wrong" } } } },
      { publicKeyPemOrDer: kp.publicKeyPem, ensRecord: runtimeEnsFixture }
    );
    assert.equal(badKid.ok, false);

    const badCanonical = verifyCommandLayerReceipt(
      { ...signed, metadata: { ...signed.metadata!, proof: { ...signed.metadata!.proof!, canonicalization: "json.unsorted.v1" } } },
      { publicKeyPemOrDer: kp.publicKeyPem, ensRecord: runtimeEnsFixture }
    );
    assert.equal(badCanonical.ok, false);

    const badSigner = verifyCommandLayerReceipt(
      { ...signed, agent: "other.commandlayer.eth" },
      { publicKeyPemOrDer: kp.publicKeyPem, ensRecord: runtimeEnsFixture }
    );
    assert.equal(badSigner.ok, false);
  });

  test("rejects legacy fields as canonical", () => {
    const legacyLike = {
      ...baseReceipt,
      metadata: { proof: { signature_b64: "abc", hash_sha256: "def", canonicalization: "json.sorted_keys.v1" } },
    };
    const result = verifyCommandLayerReceipt(legacyLike as never, { publicKeyPemOrDer: kp.publicKeyPem });
    assert.equal(result.ok, false);
  });
});
