import { createHash, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify, type KeyLike } from 'node:crypto';
import { fromBase64Url, toBase64Url } from './encoding.js';
import type {
  AttachProofOptions,
  CommonsReceipt,
  LayeredReceipt,
  Proof,
  ReceiptRuntimeMetadata,
  SignOptions,
  SignedLayeredReceipt,
  SignedReceipt,
  VerifyOptions
} from './types.js';

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

export function buildReceipt(input: CommonsReceipt): CommonsReceipt {
  return {
    verb: input.verb,
    version: input.version,
    x402: input.x402,
    trace: input.trace,
    payload: input.payload,
    status: input.status,
    result: input.result
  };
}

/** @deprecated Use buildReceipt to create the canonical commons receipt. */
export const buildUnsignedReceipt = buildReceipt;

export function createLayeredReceipt(receipt: CommonsReceipt, runtime?: ReceiptRuntimeMetadata): LayeredReceipt {
  return {
    receipt: buildReceipt(receipt),
    ...(runtime ? { runtime: { ...runtime } } : {})
  };
}

export function canonicalizeReceipt(receipt: CommonsReceipt): string {
  const sorted = sortValue(receipt);
  return JSON.stringify(sorted);
}

export function hashReceiptCanonical(canonical: string): Uint8Array {
  return createHash('sha256').update(canonical, 'utf8').digest();
}

export function attachProof(receipt: CommonsReceipt, options: AttachProofOptions): SignedLayeredReceipt {
  const proof: Proof = {
    alg: options.alg,
    signer_id: options.signer_id,
    canonical: options.canonical,
    signature: options.signature,
    ...(options.kid ? { kid: options.kid } : {})
  };

  return {
    receipt: buildReceipt(receipt),
    signature: { proof }
  };
}

export function signReceiptEd25519(receipt: CommonsReceipt, options: SignOptions): SignedLayeredReceipt {
  const canonical = options.canonical ?? DEFAULT_CANONICAL;
  const canonicalReceipt = canonicalizeReceipt(receipt);
  const signature = cryptoSign(null, Buffer.from(canonicalReceipt, 'utf8'), normalizePrivateKey(options.privateKey));

  return attachProof(receipt, {
    alg: 'ed25519',
    kid: options.kid,
    signer_id: options.signer_id,
    canonical,
    signature: toBase64Url(new Uint8Array(signature))
  });
}

export function verifyReceiptSignature(receipt: SignedLayeredReceipt, options: VerifyOptions): boolean {
  const canonical = options.canonical ?? DEFAULT_CANONICAL;
  const proof = receipt.signature?.proof;
  if (!proof || proof.alg !== 'ed25519' || proof.canonical !== canonical) {
    return false;
  }

  const canonicalReceipt = canonicalizeReceipt(receipt.receipt);
  return cryptoVerify(
    null,
    Buffer.from(canonicalReceipt, 'utf8'),
    normalizePublicKey(options.pubkey),
    Buffer.from(fromBase64Url(proof.signature))
  );
}

/**
 * @deprecated Converts a layered signed receipt into the legacy metadata.proof envelope.
 */
export function toLegacySignedReceipt(receipt: SignedLayeredReceipt, runtimeMetadata: Record<string, unknown> = {}): SignedReceipt {
  return {
    ...buildReceipt(receipt.receipt),
    metadata: {
      ...runtimeMetadata,
      proof: receipt.signature.proof
    }
  };
}
