import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import {
  signReceiptEd25519Sha256,
  verifyReceiptEd25519Sha256,
} from "../dist/index.js";

test("runtime-core: sign → verify roundtrip works", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
  const publicPem = publicKey.export({ type: "spki", format: "pem" });

  const receipt = {
    x402: { verb: "test", version: "1.1.0" },
    trace: { trace_id: "trace_test_1" },
    status: "success",
    result: { ok: true },
  };

  const layeredReceipt = signReceiptEd25519Sha256(receipt, {
    signer_id: "runtime.commandlayer.eth",
    kid: "testkid",
    canonical: "json.sorted_keys.v1",
    privateKeyPem: privatePem,
  });

  assert.ok(layeredReceipt.signature?.proof.hash_sha256);
  assert.ok(layeredReceipt.signature?.proof.signature_b64);

  const result = verifyReceiptEd25519Sha256(layeredReceipt, {
    publicKeyPemOrDer: publicPem,
    allowedCanonicals: ["json.sorted_keys.v1"],
  });

  assert.equal(result.ok, true);
});
