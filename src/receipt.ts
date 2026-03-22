import { createHash, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify, type KeyLike } from 'node:crypto';
import { fromBase64Url, toBase64Url } from './encoding.js';
import {
  COMMAND_LAYER_CURRENT_LINE,
  COMMONS_CONTRACT,
  COMMERCIAL_CONTRACT,
  DEFAULT_CANONICAL_ID
} from './types.js';
import type {
  AttachProofOptions,
  CommandLayerReceipt,
  CommercialReceipt,
  CommonsReceipt,
  LayeredReceipt,
  LegacySignedReceiptEnvelope,
  Proof,
  ReceiptRuntimeMetadata,
  SignOptions,
  SignedLayeredReceipt,
  VerifyOptions
} from './types.js';

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, val]) => [key, sortValue(val)])
    );
  }
  return value;
}

function toEd25519PublicSpki(raw32: Uint8Array): Uint8Array {
  if (raw32.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  return Buffer.concat([prefix, Buffer.from(raw32)]);
}

function normalizePrivateKey(privateKey: Uint8Array | string): KeyLike {
  return typeof privateKey === 'string'
    ? createPrivateKey(privateKey)
    : createPrivateKey({ key: Buffer.from(privateKey), format: 'der', type: 'pkcs8' });
}

function normalizePublicKey(pubkey: Uint8Array | string): KeyLike {
  if (typeof pubkey === 'string') {
    if (pubkey.includes('BEGIN PUBLIC KEY')) return createPublicKey(pubkey);
    return createPublicKey({ key: toEd25519PublicSpki(fromBase64Url(pubkey)), format: 'der', type: 'spki' });
  }
  if (pubkey.length === 32) {
    return createPublicKey({ key: toEd25519PublicSpki(pubkey), format: 'der', type: 'spki' });
  }
  return createPublicKey({ key: Buffer.from(pubkey), format: 'der', type: 'spki' });
}

export function buildCommonsReceipt(input: Omit<CommonsReceipt, 'line' | 'contract'> & Partial<Pick<CommonsReceipt, 'line' | 'contract'>>): CommonsReceipt {
  return {
    line: COMMAND_LAYER_CURRENT_LINE,
    contract: COMMONS_CONTRACT,
    verb: input.verb,
    version: input.version,
    payload: input.payload,
    status: input.status,
    ...(input.trace ? { trace: input.trace } : {}),
    ...(Object.prototype.hasOwnProperty.call(input, 'result') ? { result: input.result } : {}),
    ...(Object.prototype.hasOwnProperty.call(input, 'error') ? { error: input.error } : {})
  };
}

export function buildCommercialReceipt(
  input: Omit<CommercialReceipt, 'line' | 'contract'> & Partial<Pick<CommercialReceipt, 'line' | 'contract'>>
): CommercialReceipt {
  const commons = buildCommonsReceipt({
    verb: input.verb,
    version: input.version,
    trace: input.trace,
    payload: input.payload,
    status: input.status,
    ...(Object.prototype.hasOwnProperty.call(input, 'result') ? { result: input.result } : {}),
    ...(Object.prototype.hasOwnProperty.call(input, 'error') ? { error: input.error } : {})
  });

  return {
    ...commons,
    contract: COMMERCIAL_CONTRACT,
    commercial: { ...input.commercial }
  };
}

export function buildReceipt(input: CommandLayerReceipt): CommandLayerReceipt {
  return input.contract === COMMERCIAL_CONTRACT ? buildCommercialReceipt(input) : buildCommonsReceipt(input);
}

export function createLayeredReceipt<TReceipt extends CommandLayerReceipt>(
  receipt: TReceipt,
  runtime?: ReceiptRuntimeMetadata
): LayeredReceipt<TReceipt> {
  return {
    receipt: buildReceipt(receipt) as TReceipt,
    ...(runtime ? { runtime: { ...runtime } } : {})
  };
}

export function canonicalizeReceipt(receipt: CommandLayerReceipt): string {
  return JSON.stringify(sortValue(buildReceipt(receipt)));
}

export function hashReceiptCanonical(canonical: string): Uint8Array {
  return createHash('sha256').update(canonical, 'utf8').digest();
}

export function attachProof<TReceipt extends CommandLayerReceipt>(receipt: TReceipt, options: AttachProofOptions): SignedLayeredReceipt<TReceipt> {
  const proof: Proof = {
    alg: options.alg,
    signer_id: options.signer_id,
    canonical: options.canonical,
    signature: options.signature,
    ...(options.kid ? { kid: options.kid } : {})
  };

  return {
    receipt: buildReceipt(receipt) as TReceipt,
    signature: { proof }
  };
}

export function signReceiptEd25519<TReceipt extends CommandLayerReceipt>(receipt: TReceipt, options: SignOptions): SignedLayeredReceipt<TReceipt> {
  const canonical = options.canonical ?? DEFAULT_CANONICAL_ID;
  const signature = cryptoSign(null, Buffer.from(canonicalizeReceipt(receipt), 'utf8'), normalizePrivateKey(options.privateKey));
  return attachProof(receipt, {
    alg: 'ed25519',
    kid: options.kid,
    signer_id: options.signer_id,
    canonical,
    signature: toBase64Url(new Uint8Array(signature))
  });
}

export function verifyReceiptSignature(receipt: SignedLayeredReceipt, options: VerifyOptions): boolean {
  const canonical = options.canonical ?? DEFAULT_CANONICAL_ID;
  const proof = receipt.signature?.proof;
  if (!proof || proof.alg !== 'ed25519' || proof.canonical !== canonical) return false;

  return cryptoVerify(
    null,
    Buffer.from(canonicalizeReceipt(receipt.receipt), 'utf8'),
    normalizePublicKey(options.pubkey),
    Buffer.from(fromBase64Url(proof.signature))
  );
}

/** @deprecated Legacy 1.0.0 metadata.proof envelope. */
export function toLegacySignedReceipt(
  receipt: SignedLayeredReceipt,
  runtimeMetadata: Record<string, unknown> = {}
): LegacySignedReceiptEnvelope {
  const built = buildReceipt(receipt.receipt);
  return {
    ...(built.contract === COMMERCIAL_CONTRACT ? { x402: built.commercial } : {}),
    verb: built.verb,
    version: String(built.version),
    ...(built.trace ? { trace: built.trace } : {}),
    payload: built.payload,
    status: built.status,
    ...(Object.prototype.hasOwnProperty.call(built, 'result') ? { result: built.result } : {}),
    metadata: {
      ...runtimeMetadata,
      proof: receipt.signature.proof
    }
  };
}
