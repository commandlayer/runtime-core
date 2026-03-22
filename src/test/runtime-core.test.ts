import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  buildCommercialReceipt,
  buildCommonsReceipt,
  buildSchemaPath,
  canonicalizeReceipt,
  COMMAND_LAYER_CURRENT_LINE,
  COMMONS_CONTRACT,
  COMMERCIAL_CONTRACT,
  createLayeredReceipt,
  extractEd25519Raw32FromSpkiDer,
  hashReceiptCanonical,
  normalizeCommonsRequest,
  normalizeCommercialRequest,
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

test('normalizeRequest defaults to Commons and ignores legacy x402 metadata', () => {
  const normalized = normalizeRequest({ x402: { a: 1 }, trace: { t: '1' }, input: { hello: 'world' } });
  assert.deepEqual(normalized, {
    trace: { t: '1' },
    payload: { hello: 'world' }
  });
});

test('normalizeCommercialRequest keeps commercial metadata separate from Commons payload', () => {
  const normalized = normalizeCommercialRequest({
    commercial: { plan: 'pro', settlement: 'required' },
    trace: { request_id: 'req_1' },
    payload: { hello: 'world' }
  });

  assert.deepEqual(normalized, {
    commercial: { plan: 'pro', settlement: 'required' },
    trace: { request_id: 'req_1' },
    payload: { hello: 'world' }
  });
});

test('buildSchemaPath uses the v1.1.0 current-line layout', () => {
  assert.equal(
    buildSchemaPath({ contract: COMMONS_CONTRACT, verb: 'chat.completions', kind: 'request' }),
    '/schemas/1.1.0/commons/chat.completions/v1/request.schema.json'
  );
  assert.equal(
    buildSchemaPath({ contract: COMMERCIAL_CONTRACT, verb: 'chat.completions', version: 'v2', kind: 'receipt' }),
    '/schemas/1.1.0/commercial/chat.completions/v2/receipt.schema.json'
  );
});

test('parse PEM SPKI to raw 32-byte key and base64url', () => {
  const raw = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i));
  const spkiDer = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw)]);
  const pem = `-----BEGIN PUBLIC KEY-----\n${spkiDer.toString('base64')}\n-----END PUBLIC KEY-----`;

  const parsedRaw = extractEd25519Raw32FromSpkiDer(parsePemToDer(pem));
  assert.equal(parsedRaw.length, 32);
  assert.equal(toBase64Url(parsedRaw), 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8');
});

test('canonicalize + hash are deterministic on current-line Commons receipts', () => {
  const fixture = buildCommonsReceipt({
    verb: 'test.verb',
    version: 'v1',
    trace: { z: 'last', a: 'first' },
    payload: { two: 2, one: 1 },
    status: 'ok',
    result: { arr: [{ y: 2, x: 1 }] }
  });

  const canonical = canonicalizeReceipt(fixture);
  assert.equal(
    canonical,
    '{"contract":"commons","line":"1.1.0","payload":{"one":1,"two":2},"result":{"arr":[{"x":1,"y":2}]},"status":"ok","trace":{"a":"first","z":"last"},"verb":"test.verb","version":"v1"}'
  );

  const hash = Buffer.from(hashReceiptCanonical(canonical)).toString('hex');
  assert.equal(hash, '51b9aeefb9b41a4f8b1c1ae94c996e2dfef440721f30c5185cfe8c6d2354a628');
});

test('createLayeredReceipt preserves current-line receipt/runtime separation', () => {
  const commons = createLayeredReceipt(
    buildCommonsReceipt({
      verb: 'test.verb',
      version: 'v1',
      trace: { request_id: 'req_1' },
      payload: { hello: 'world' },
      status: 'ok',
      result: { ok: true }
    }),
    { execution: { duration_ms: 12 } }
  );
  assert.equal(commons.receipt.contract, COMMONS_CONTRACT);
  assert.equal(commons.receipt.line, COMMAND_LAYER_CURRENT_LINE);
  assert.deepEqual(commons.runtime, { execution: { duration_ms: 12 } });

  const commercial = createLayeredReceipt(
    buildCommercialReceipt({
      verb: 'test.verb',
      version: 'v1',
      commercial: { plan: 'pro' },
      trace: { request_id: 'req_2' },
      payload: { hello: 'world' },
      status: 'ok',
      result: { ok: true }
    })
  );
  assert.deepEqual(commercial.receipt.commercial, { plan: 'pro' });
});

test('sign/verify pipeline keeps proof outside the canonical receipt', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  const spki = publicKey.export({ format: 'der', type: 'spki' });

  const receipt = signReceiptEd25519(
    buildCommercialReceipt({
      verb: 'test.verb',
      version: 'v1',
      commercial: { settlement: 'required' },
      trace: {},
      payload: { hello: 'world' },
      status: 'ok',
      result: { ok: true }
    }),
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
  assert.deepEqual(legacyReceipt.x402, { settlement: 'required' });
});

test('legacy 1.0.0 tampered receipt fails verification', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

  const signedReceipt = signReceiptEd25519Sha256(
    {
      verb: 'test',
      version: '1.0.0',
      x402: { plan: 'legacy' },
      trace: { trace_id: 'trace_123' },
      payload: { hello: 'world' },
      status: 'success',
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
