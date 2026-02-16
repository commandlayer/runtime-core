import { createHash, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify, type KeyLike } from 'node:crypto';
import { fromBase64Url, toBase64Url } from './encoding.js';
import type { AttachProofOptions, Proof, SignOptions, SignedReceipt, UnsignedReceipt, VerifyOptions } from './types.js';

const DEFAULT_CANONICAL = 'json.sorted_keys.v1';

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, val]) => [key, sortValue(val)]);
    return Object.fromEntries(entries);
  }
  return value;
}

function toEd25519PublicSpki(raw32: Uint8Array): Uint8Array {
  if (raw32.length !== 32) {
    throw new Error('Ed25519 public key must be 32 bytes');
  }
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  return Buffer.concat([prefix, Buffer.from(raw32)]);
}

function normalizePrivateKey(privateKey: Uint8Array | string): KeyLike {
  if (typeof privateKey === 'string') {
    return createPrivateKey(privateKey);
  }
  return createPrivateKey({ key: Buffer.from(privateKey), format: 'der', type: 'pkcs8' });
}

function normalizePublicKey(pubkey: Uint8Array | string): KeyLike {
  if (typeof pubkey === 'string') {
    if (pubkey.includes('BEGIN PUBLIC KEY')) {
      return createPublicKey(pubkey);
    }
    const decoded = fromBase64Url(pubkey);
    return createPublicKey({ key: toEd25519PublicSpki(decoded), format: 'der', type: 'spki' });
  }
  if (pubkey.length === 32) {
    return createPublicKey({ key: toEd25519PublicSpki(pubkey), format: 'der', type: 'spki' });
  }
  return createPublicKey({ key: Buffer.from(pubkey), format: 'der', type: 'spki' });
}

export function buildUnsignedReceipt(input: UnsignedReceipt): UnsignedReceipt {
  return {
    verb: input.verb,
    version: input.version,
    x402: input.x402,
    trace: input.trace,
    payload: input.payload,
    status: input.status,
    result: input.result,
    metadata: input.metadata ? { ...input.metadata } : undefined
  };
}

export function canonicalizeReceipt(unsigned: UnsignedReceipt): string {
  const sorted = sortValue(unsigned);
  return JSON.stringify(sorted);
}

export function hashReceiptCanonical(canonical: string): Uint8Array {
  return createHash('sha256').update(canonical, 'utf8').digest();
}

export function attachProof(unsigned: UnsignedReceipt, options: AttachProofOptions): SignedReceipt {
  const metadata = { ...(unsigned.metadata ?? {}) } as Record<string, unknown>;
  const proof: Proof = {
    alg: options.alg,
    signer_id: options.signer_id,
    canonical: options.canonical,
    signature: options.signature,
    ...(options.kid ? { kid: options.kid } : {})
  };

  metadata.proof = proof;
  return {
    ...unsigned,
    metadata: metadata as SignedReceipt['metadata']
  };
}

export function signReceiptEd25519(unsigned: UnsignedReceipt, options: SignOptions): SignedReceipt {
  const canonical = options.canonical ?? DEFAULT_CANONICAL;
  const canonicalReceipt = canonicalizeReceipt(unsigned);
  const signature = cryptoSign(null, Buffer.from(canonicalReceipt, 'utf8'), normalizePrivateKey(options.privateKey));

  return attachProof(unsigned, {
    alg: 'ed25519',
    kid: options.kid,
    signer_id: options.signer_id,
    canonical,
    signature: toBase64Url(new Uint8Array(signature))
  });
}

export function verifyReceiptSignature(receipt: SignedReceipt, options: VerifyOptions): boolean {
  const canonical = options.canonical ?? DEFAULT_CANONICAL;
  const proof = receipt.metadata?.proof;
  if (!proof || proof.alg !== 'ed25519' || proof.canonical !== canonical) {
    return false;
  }

  const { metadata: _meta, ...withoutMetadata } = receipt;
  const unsigned: UnsignedReceipt = {
    ...withoutMetadata,
    metadata: (() => {
      const metadata = { ...(receipt.metadata ?? {}) };
      delete (metadata as Record<string, unknown>).proof;
      return Object.keys(metadata).length ? metadata : undefined;
    })()
  };

  const canonicalReceipt = canonicalizeReceipt(unsigned);
  return cryptoVerify(
    null,
    Buffer.from(canonicalReceipt, 'utf8'),
    normalizePublicKey(options.pubkey),
    Buffer.from(fromBase64Url(proof.signature))
  );
}
