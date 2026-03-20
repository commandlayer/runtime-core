import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  canonicalizeReceipt,
  createLayeredReceipt,
  extractEd25519Raw32FromSpkiDer,
  hashReceiptCanonical,
  normalizeRequest,
  parsePemToDer,
  signReceiptEd25519Sha256,
  signReceiptEd25519,
  toBase64Url,
  toLegacyReceiptEnvelope,
  toLegacySignedReceipt,
  verifyReceiptEd25519Sha256,
  verifyReceiptSignature
} from '../index.js';

test('normalizeRequest maps legacy input to payload', () => {
  const normalized = normalizeRequest({ x402: { a: 1 }, trace: { t: '1' }, input: { hello: 'world' } });
  assert.deepEqual(normalized, {
    x402: { a: 1 },
    trace: { t: '1' },
    payload: { hello: 'world' }
  });
});

test('parse PEM SPKI to raw 32-byte key and base64url', () => {
  const raw = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i));
  const spkiDer = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw)]);
  const pem = `-----BEGIN PUBLIC KEY-----\n${spkiDer.toString('base64')}\n-----END PUBLIC KEY-----`;

  const parsedRaw = extractEd25519Raw32FromSpkiDer(parsePemToDer(pem));
  assert.equal(parsedRaw.length, 32);
  assert.equal(toBase64Url(parsedRaw), 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8');
});

test('canonicalize + hash are deterministic on fixture', () => {
  const fixture = {
    verb: 'test.verb',
    version: 'v1',
    x402: { b: 2, a: 1 },
    trace: { z: 'last', a: 'first' },
    payload: { two: 2, one: 1 },
    status: 'ok',
    result: { arr: [{ y: 2, x: 1 }] }
  };

  const canonical = canonicalizeReceipt(fixture);
  assert.equal(
    canonical,
    '{"payload":{"one":1,"two":2},"result":{"arr":[{"x":1,"y":2}]},"status":"ok","trace":{"a":"first","z":"last"},"verb":"test.verb","version":"v1","x402":{"a":1,"b":2}}'
  );

  const hash = Buffer.from(hashReceiptCanonical(canonical)).toString('hex');
  assert.equal(hash, 'a125bc2ba480dc539a18be254d9dd61f0d991ba98104a7cd7cd0d169f1d50c09');
});

test('createLayeredReceipt preserves receipt/runtime separation', () => {
  const layered = createLayeredReceipt(
    {
      verb: 'test.verb',
      version: 'v1',
      x402: { policy: 'standard' },
      trace: { request_id: 'req_1' },
      payload: { hello: 'world' },
      status: 'ok',
      result: { ok: true }
    },
    { execution: { duration_ms: 12 } }
  );

  assert.deepEqual(layered.receipt, {
    verb: 'test.verb',
    version: 'v1',
    x402: { policy: 'standard' },
    trace: { request_id: 'req_1' },
    payload: { hello: 'world' },
    status: 'ok',
    result: { ok: true }
  });
  assert.deepEqual(layered.runtime, { execution: { duration_ms: 12 } });
});

test('sign/verify pipeline keeps proof outside the canonical receipt', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  const spki = publicKey.export({ format: 'der', type: 'spki' });

  const receipt = signReceiptEd25519(
    {
      verb: 'test.verb',
      version: 'v1',
      x402: {},
      trace: {},
      payload: { hello: 'world' },
      status: 'ok',
      result: { ok: true }
    },
    {
      privateKey: privatePem,
      signer_id: 'ens:test.eth',
      kid: 'k1'
    }
  );

  assert.equal(receipt.signature.proof.alg, 'ed25519');
  assert.equal(verifyReceiptSignature(receipt, { pubkey: new Uint8Array(spki) }), true);

  const legacyReceipt = toLegacySignedReceipt(receipt, { execution: { duration_ms: 12 } });
  assert.equal(legacyReceipt.metadata.proof.signer_id, 'ens:test.eth');
  assert.deepEqual(legacyReceipt.metadata.execution, { duration_ms: 12 });
});

test('runtime-core: tampered receipt fails verification', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');

  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

  const signedReceipt = signReceiptEd25519Sha256(
    {
      status: 'success',
      x402: { verb: 'test', version: '1.1.0' },
      trace: { trace_id: 'trace_123' },
      result: { ok: true }
    },
    {
      signer_id: 'runtime.commandlayer.eth',
      kid: 'testkid',
      canonical: 'json.sorted_keys.v1',
      privateKeyPem: privatePem
    }
  );

  const legacyReceipt = toLegacyReceiptEnvelope(signedReceipt);
  legacyReceipt.result = { ok: false };

  const result = verifyReceiptEd25519Sha256(legacyReceipt, {
    publicKeyPemOrDer: publicPem,
    allowedCanonicals: ['json.sorted_keys.v1']
  });

  assert.equal(result.ok, false);
  assert.equal(result.checks.hash_matches, false);
  assert.equal(result.reason, 'hash_mismatch');
});
