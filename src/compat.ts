/**
 * @commandlayer/runtime-core — compat.ts
 *
 * Backward-compatibility shims for runtime/server.mjs.
 * These adapters translate between the runtime's envelope format
 * (receipt with metadata.proof) and the core v1.1.0 APIs.
 *
 * The signing protocol is ALWAYS Ed25519(UTF8(canonical)) — raw bytes.
 * The "sha256" in function names is a legacy artifact; these functions
 * produce v1.1.0-compliant signatures.
 */

import { createHash } from "node:crypto";
import { canonicalize } from "./canonicalize.js";
import { signCanonical, verifyCanonical, CANONICAL_METHOD } from "./crypto.js";

/** Canonical method identifier constant for import by downstream repos. */
export const CANONICAL_ID_SORTED_KEYS_V1 = CANONICAL_METHOD;

// ── Runtime receipt shape (envelope format used by runtime/server.mjs) ────────

export interface RuntimeReceipt {
  verb: string;
  version?: string;
  agent?: string;
  timestamp?: string;
  metadata?: {
    proof?: RuntimeProof;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface RuntimeProof {
  alg: string;
  kid: string;
  signer_id: string;
  canonical: string;
  hash_sha256?: string;
  signature?: string;
  signature_b64?: string;
}

// ── Sign ──────────────────────────────────────────────────────────────────────

export interface SignReceiptCompatOptions {
  signer_id: string;
  kid: string;
  canonical_id?: string;
  privateKeyPem: string;
}

export interface SignedRuntimeReceipt extends RuntimeReceipt {
  metadata: {
    proof: RuntimeProof;
    [key: string]: unknown;
  };
}

/**
 * Sign a runtime-style receipt and embed the proof in metadata.proof.
 *
 * Signing message: Ed25519(UTF8(canonicalize(receipt_without_proof)))
 * The proof block is NOT included in the signed payload.
 *
 * Returns the receipt with metadata.proof populated.
 */
export function signReceiptEd25519Sha256(
  receipt: RuntimeReceipt,
  opts: SignReceiptCompatOptions
): SignedRuntimeReceipt {
  // Strip any existing proof so it's not included in the signed payload
  const { metadata: meta = {}, ...rest } = receipt;
  const { proof: _proof, ...metaWithoutProof } = meta;

  const payloadToSign: Record<string, unknown> = { ...rest, metadata: metaWithoutProof };
  if (Object.keys(metaWithoutProof).length === 0) {
    delete payloadToSign.metadata;
  }

  const canonical = canonicalize(payloadToSign);
  const sha256Hex = createHash("sha256").update(canonical, "utf8").digest("hex");
  const signature = signCanonical(canonical, opts.privateKeyPem);

  const proof: RuntimeProof = {
    alg: "ed25519",
    kid: opts.kid,
    signer_id: opts.signer_id,
    canonical: opts.canonical_id ?? CANONICAL_METHOD,
    hash_sha256: sha256Hex,
    signature_b64: signature,
    signature,
  };

  return {
    ...rest,
    metadata: {
      ...metaWithoutProof,
      proof,
    },
  } as SignedRuntimeReceipt;
}

// ── Verify ────────────────────────────────────────────────────────────────────

export interface VerifyReceiptCompatOptions {
  publicKeyPemOrDer: string;
  allowedCanonicals?: string[];
}

export interface VerifyReceiptCompatResult {
  ok: boolean;
  checks: {
    signature_valid: boolean;
    hash_matches: boolean;
  };
  reason?: string;
}

/**
 * Verify a runtime-style receipt (with metadata.proof).
 *
 * Reconstructs the signed payload by stripping metadata.proof,
 * then verifies the Ed25519 signature over the canonical bytes.
 *
 * Also recomputes sha256 and checks hash_sha256 if present (legacy compat).
 */
export function verifyReceiptEd25519Sha256(
  receipt: RuntimeReceipt,
  opts: VerifyReceiptCompatOptions
): VerifyReceiptCompatResult {
  const checks = { signature_valid: false, hash_matches: false };

  const proof = receipt?.metadata?.proof;
  if (!proof) {
    return { ok: false, checks, reason: "Missing metadata.proof" };
  }

  const sig = proof.signature || proof.signature_b64;
  if (!sig) {
    return { ok: false, checks, reason: "Missing proof.signature" };
  }

  const allowedCanonicals = opts.allowedCanonicals ?? [CANONICAL_METHOD];
  if (!allowedCanonicals.includes(proof.canonical)) {
    return {
      ok: false,
      checks,
      reason: `Unsupported canonicalization method: ${proof.canonical}`,
    };
  }

  // Reconstruct the signed payload (receipt without the proof block)
  const { metadata: meta = {}, ...rest } = receipt;
  const { proof: _proof, ...metaWithoutProof } = meta;

  const payloadToVerify: Record<string, unknown> = { ...rest, metadata: metaWithoutProof };
  if (Object.keys(metaWithoutProof).length === 0) {
    delete payloadToVerify.metadata;
  }

  let canonical: string;
  try {
    canonical = canonicalize(payloadToVerify);
  } catch (err) {
    return {
      ok: false,
      checks,
      reason: `Canonicalization failed: ${(err as Error).message}`,
    };
  }

  // Verify sha256 hash if present (legacy field, not required for v1.1.0)
  if (proof.hash_sha256) {
    const recomputed = createHash("sha256").update(canonical, "utf8").digest("hex");
    checks.hash_matches = recomputed === proof.hash_sha256;
  } else {
    checks.hash_matches = true;
  }

  // Verify signature over raw canonical bytes (v1.1.0 protocol)
  try {
    checks.signature_valid = verifyCanonical(canonical, sig, opts.publicKeyPemOrDer);
  } catch {
    return { ok: false, checks, reason: "Signature verification threw an error" };
  }

  const ok = checks.signature_valid && checks.hash_matches;
  return {
    ok,
    checks,
    reason: ok
      ? undefined
      : [
          !checks.signature_valid ? "signature invalid" : null,
          !checks.hash_matches ? "hash mismatch" : null,
        ]
          .filter(Boolean)
          .join(", "),
  };
}
