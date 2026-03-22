import { canonicalizeSortedKeysV1, CANONICAL_ID_SORTED_KEYS_V1 } from './canonical.js';
import { sha256HexUtf8, signEd25519MessageBase64, verifyEd25519MessageBase64, base64UrlToBase64 } from './crypto.js';

/**
 * Legacy 1.0.0 receipt verification bridge.
 * Kept only for consumers still reading metadata.proof or hash-bound ed25519-sha256 receipts.
 */

export type LegacyReceiptStatus = 'success' | 'error' | 'delegated';

export type ReceiptProof = {
  alg: 'ed25519-sha256' | string;
  canonical: string;
  signer_id: string;
  kid?: string;
  hash_sha256: string;
  signature_b64?: string;
  signature?: string;
};

export type LegacyReceiptBase = {
  verb?: string;
  version?: string;
  x402?: { [k: string]: any };
  trace?: { [k: string]: any };
  payload?: any;
  status: LegacyReceiptStatus;
  result?: any;
  error?: any;
  metadata?: Record<string, unknown> & {
    proof?: ReceiptProof;
    receipt_id?: string;
  };
  [k: string]: any;
};

export type ReceiptSignatureLayer = {
  proof: ReceiptProof;
  receipt_id?: string;
};

export type LayeredReceiptV1 = {
  receipt: Omit<LegacyReceiptBase, 'metadata'>;
  runtime?: Record<string, unknown>;
  signature?: ReceiptSignatureLayer;
};

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value));
}

export function buildCanonicalReceipt(receipt: Omit<LegacyReceiptBase, 'metadata'>): Omit<LegacyReceiptBase, 'metadata'> {
  return clone(receipt);
}

export function computeReceiptCanonicalAndHash(receipt: Omit<LegacyReceiptBase, 'metadata'>): { canonical: string; hash_sha256: string } {
  const canonical = canonicalizeSortedKeysV1(buildCanonicalReceipt(receipt));
  return { canonical, hash_sha256: sha256HexUtf8(canonical) };
}

export type LegacySignOptions = {
  signer_id: string;
  kid?: string;
  canonical?: string;
  privateKeyPem: string;
};

export function signReceiptEd25519Sha256(receipt: Omit<LegacyReceiptBase, 'metadata'>, opts: LegacySignOptions): LayeredReceiptV1 {
  const canonicalId = opts.canonical ?? CANONICAL_ID_SORTED_KEYS_V1;
  if (canonicalId !== CANONICAL_ID_SORTED_KEYS_V1) {
    throw new Error(`Unsupported canonical '${canonicalId}'. Expected '${CANONICAL_ID_SORTED_KEYS_V1}'.`);
  }

  const { hash_sha256 } = computeReceiptCanonicalAndHash(receipt);
  const proof: ReceiptProof = {
    alg: 'ed25519-sha256',
    canonical: CANONICAL_ID_SORTED_KEYS_V1,
    signer_id: opts.signer_id,
    ...(opts.kid ? { kid: opts.kid } : {}),
    hash_sha256,
    signature_b64: signEd25519MessageBase64(hash_sha256, opts.privateKeyPem)
  };

  return {
    receipt: buildCanonicalReceipt(receipt),
    signature: {
      proof,
      receipt_id: hash_sha256
    }
  };
}

export type LegacyVerifyOptions = {
  publicKeyPemOrDer: string;
  allowedCanonicals?: string[];
  requireKid?: string;
  requireSignerId?: string;
};

export type VerifyReceiptChecks = {
  hash_matches: boolean;
  signature_matches: boolean;
};

export type VerifyReceiptResult = {
  ok: boolean;
  reason?: string;
  checks: VerifyReceiptChecks;
};

function toLayeredReceiptV1(receipt: LayeredReceiptV1 | LegacyReceiptBase): LayeredReceiptV1 {
  if ('receipt' in receipt && receipt.receipt) return receipt as LayeredReceiptV1;
  const legacyReceipt = clone(receipt as LegacyReceiptBase);
  const metadata = legacyReceipt.metadata;
  delete legacyReceipt.metadata;

  return {
    receipt: legacyReceipt,
    ...(metadata?.proof
      ? { signature: { proof: metadata.proof, ...(typeof metadata.receipt_id === 'string' ? { receipt_id: metadata.receipt_id } : {}) } }
      : {})
  };
}

export function verifyReceiptEd25519Sha256(receipt: LayeredReceiptV1 | LegacyReceiptBase, opts: LegacyVerifyOptions): VerifyReceiptResult {
  const layeredReceipt = toLayeredReceiptV1(receipt);
  const proof = layeredReceipt.signature?.proof;
  if (!proof) return { ok: false, reason: 'missing_proof', checks: { hash_matches: false, signature_matches: false } };
  if (opts.requireSignerId && proof.signer_id !== opts.requireSignerId) {
    return { ok: false, reason: 'signer_id_mismatch', checks: { hash_matches: false, signature_matches: false } };
  }
  if (opts.requireKid && proof.kid !== opts.requireKid) {
    return { ok: false, reason: 'kid_mismatch', checks: { hash_matches: false, signature_matches: false } };
  }
  const allowedCanonicals = opts.allowedCanonicals ?? [CANONICAL_ID_SORTED_KEYS_V1];
  if (!allowedCanonicals.includes(proof.canonical)) {
    return { ok: false, reason: 'canonical_not_allowed', checks: { hash_matches: false, signature_matches: false } };
  }
  if (proof.alg !== 'ed25519-sha256') {
    return { ok: false, reason: 'unsupported_alg', checks: { hash_matches: false, signature_matches: false } };
  }

  const { hash_sha256 } = computeReceiptCanonicalAndHash(layeredReceipt.receipt);
  if (typeof proof.hash_sha256 !== 'string' || proof.hash_sha256.length !== 64) {
    return { ok: false, reason: 'missing_or_invalid_hash', checks: { hash_matches: false, signature_matches: false } };
  }
  if (hash_sha256 !== proof.hash_sha256) {
    return { ok: false, reason: 'hash_mismatch', checks: { hash_matches: false, signature_matches: false } };
  }

  const sigB64 = typeof proof.signature_b64 === 'string' && proof.signature_b64
    ? proof.signature_b64
    : typeof proof.signature === 'string' && proof.signature
      ? base64UrlToBase64(proof.signature)
      : null;
  if (!sigB64) return { ok: false, reason: 'missing_signature', checks: { hash_matches: true, signature_matches: false } };

  return verifyEd25519MessageBase64(hash_sha256, sigB64, opts.publicKeyPemOrDer)
    ? { ok: true, checks: { hash_matches: true, signature_matches: true } }
    : { ok: false, reason: 'bad_signature', checks: { hash_matches: true, signature_matches: false } };
}

export function enforceCanonicalFromEns(layeredReceipt: LayeredReceiptV1, ensCanonical: string): { ok: boolean; reason?: string } {
  const proof = layeredReceipt.signature?.proof;
  if (!proof) return { ok: false, reason: 'missing_proof' };
  if (!ensCanonical) return { ok: false, reason: 'missing_ens_canonical' };
  if (proof.canonical !== ensCanonical) return { ok: false, reason: 'canonical_mismatch_ens' };
  return { ok: true };
}

/** @deprecated Converts the legacy layered structure back into the 1.0.0 metadata envelope. */
export function toLegacyReceiptEnvelope(layeredReceipt: LayeredReceiptV1): LegacyReceiptBase {
  const legacyReceipt = { ...buildCanonicalReceipt(layeredReceipt.receipt) } as LegacyReceiptBase;
  const metadata: Record<string, unknown> = { ...(layeredReceipt.runtime ?? {}) };
  if (layeredReceipt.signature) {
    metadata.proof = layeredReceipt.signature.proof;
    if (layeredReceipt.signature.receipt_id) metadata.receipt_id = layeredReceipt.signature.receipt_id;
  }
  if (Object.keys(metadata).length > 0) legacyReceipt.metadata = metadata as LegacyReceiptBase['metadata'];
  return legacyReceipt;
}
