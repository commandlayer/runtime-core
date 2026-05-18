/**
 * @commandlayer/runtime-core — receipt.ts
 *
 * v1.1.0 signed layered receipt builder and verifier.
 *
 * Proof field names (canonical, matches clas schema):
 *   proof.alg        — signature algorithm ("Ed25519")
 *   proof.kid        — key identifier (from ENS cl.sig.kid)
 *   proof.signer_id  — ENS name of signer (e.g. runtime.commandlayer.eth)
 *   proof.canonical  — canonicalization method ("json.sorted_keys.v1")
 *   proof.signature  — standard base64-encoded Ed25519 signature (64 bytes)
 */

import { canonicalize, CANONICAL_METHOD } from "./canonicalize.js";
import {
  signCanonical,
  verifyCanonical,
  verifyCanonicalWithRawKey,
  SIGNATURE_ALG,
  PROTOCOL_VERSION,
} from "./crypto.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ReceiptPayload {
  verb: string;
  version: string;
  agent: string;
  timestamp: string;
  [key: string]: unknown;
}

export interface ReceiptProof {
  /** Signature algorithm. Canonical "Ed25519" (legacy lowercase accepted in verification). */
  alg: typeof SIGNATURE_ALG | "ed25519";
  /** Key identifier from ENS cl.sig.kid */
  kid: string;
  /** ENS name of the signer */
  signer_id: string;
  /** Canonicalization method. Always "json.sorted_keys.v1". */
  canonical: typeof CANONICAL_METHOD;
  /** Standard base64-encoded Ed25519 signature over the canonical receipt string */
  signature: string;
}

export interface SignedLayeredReceipt {
  receipt: ReceiptPayload;
  signature: {
    proof: ReceiptProof;
  };
}

// ── Builders ──────────────────────────────────────────────────────────────────

export interface SignReceiptOptions {
  privateKeyPem: string;
  kid: string;
  signerEns: string;
}

/**
 * Build and sign a v1.1.0 layered receipt.
 *
 * Signing message: raw UTF-8 bytes of canonicalize(receipt)
 * Output signature: standard base64 (64 bytes)
 */
export function signReceipt(
  payload: ReceiptPayload,
  opts: SignReceiptOptions
): SignedLayeredReceipt {
  // Validate required fields — all four are mandated by ReceiptPayload
  if (!payload.verb || typeof payload.verb !== "string") {
    throw new Error("receipt.verb is required and must be a non-empty string");
  }
  if (!payload.version || typeof payload.version !== "string") {
    throw new Error("receipt.version is required and must be a non-empty string");
  }
  if (!payload.agent || typeof payload.agent !== "string") {
    throw new Error("receipt.agent is required and must be a non-empty string");
  }
  if (!payload.timestamp || typeof payload.timestamp !== "string") {
    throw new Error("receipt.timestamp is required and must be a non-empty string");
  }

  if (!opts.privateKeyPem || typeof opts.privateKeyPem !== "string") {
    throw new Error("signReceipt: privateKeyPem is required");
  }
  if (!opts.kid || typeof opts.kid !== "string") {
    throw new Error("signReceipt: kid is required");
  }
  if (!opts.signerEns || typeof opts.signerEns !== "string") {
    throw new Error("signReceipt: signerEns is required");
  }

  const canonical = canonicalize(payload);
  const signature = signCanonical(canonical, opts.privateKeyPem);

  return {
    receipt: payload,
    signature: {
      proof: {
        alg: SIGNATURE_ALG,
        kid: opts.kid,
        signer_id: opts.signerEns,
        canonical: CANONICAL_METHOD,
        signature,
      },
    },
  };
}

// ── Verification ──────────────────────────────────────────────────────────────

export interface VerifyReceiptResult {
  valid: boolean;
  checks: {
    structureValid: boolean;
    algValid: boolean;
    kidMatched: boolean;
    signerMatched: boolean;
    signatureValid: boolean;
  };
  reason?: string;
}

export interface VerifyReceiptOptions {
  /** Expected signer ENS name. If provided, signer_id must match. */
  expectedSigner?: string;
  /** Raw 32-byte public key. If provided, used for verification directly. */
  rawPublicKey?: Uint8Array;
  /** PEM public key. If provided, used for verification directly. */
  publicKeyPem?: string;
  /** Expected kid. If provided, proof.kid must match. */
  expectedKid?: string;
}

/**
 * Verify a v1.1.0 signed layered receipt.
 *
 * Returns a detailed result with per-check breakdown.
 * Never throws on invalid signature — only throws on missing required options.
 */
export function verifyReceipt(
  receipt: SignedLayeredReceipt,
  opts: VerifyReceiptOptions
): VerifyReceiptResult {
  if (!opts.rawPublicKey && !opts.publicKeyPem) {
    throw new Error(
      "verifyReceipt requires either rawPublicKey or publicKeyPem"
    );
  }

  const checks = {
    structureValid: false,
    algValid: false,
    kidMatched: false,
    signerMatched: false,
    signatureValid: false,
  };

  // Structure check
  const proof = receipt?.signature?.proof;
  if (
    !receipt?.receipt
    || !proof?.signature
    || typeof proof.signature !== "string"
    || proof.signature.length === 0
    || !proof?.alg
    || !proof?.signer_id
  ) {
    return {
      valid: false,
      checks,
      reason: "Receipt is missing required structure fields",
    };
  }
  checks.structureValid = true;

  // Algorithm check
  const normalizedAlg = proof.alg === "ed25519" ? SIGNATURE_ALG : proof.alg;
  if (normalizedAlg !== SIGNATURE_ALG) {
    return {
      valid: false,
      checks,
      reason: `Unsupported algorithm "${proof.alg}". Only "${SIGNATURE_ALG}" is supported.`,
    };
  }
  checks.algValid = true;

  // Kid check (if expected)
  checks.kidMatched = opts.expectedKid
    ? proof.kid === opts.expectedKid
    : true;

  // Signer check (if expected)
  checks.signerMatched = opts.expectedSigner
    ? proof.signer_id === opts.expectedSigner
    : true;

  // Signature verification
  let canonical: string;
  try {
    canonical = canonicalize(receipt.receipt);
  } catch (err) {
    return {
      valid: false,
      checks,
      reason: `Canonicalization failed: ${(err as Error).message}`,
    };
  }

  try {
    if (opts.rawPublicKey) {
      checks.signatureValid = verifyCanonicalWithRawKey(
        canonical,
        proof.signature,
        opts.rawPublicKey
      );
    } else {
      checks.signatureValid = verifyCanonical(
        canonical,
        proof.signature,
        opts.publicKeyPem!
      );
    }
  } catch (err) {
    return {
      valid: false,
      checks,
      reason: `Signature verification error: ${(err as Error).message}`,
    };
  }

  // ALL checks must pass for valid: true
  const valid =
    checks.structureValid
    && checks.algValid
    && checks.kidMatched
    && checks.signerMatched
    && checks.signatureValid;

  return {
    valid,
    checks,
    reason: valid
      ? undefined
      : Object.entries(checks)
          .filter(([, v]) => !v)
          .map(([k]) => `${k} failed`)
          .join(", "),
  };
}

/**
 * Type guard: check if an unknown value is a SignedLayeredReceipt.
 */
export function isSignedLayeredReceipt(
  value: unknown
): value is SignedLayeredReceipt {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  if (typeof v.receipt !== "object" || v.receipt === null) return false;
  if (typeof v.signature !== "object" || v.signature === null) return false;
  const sig = v.signature as Record<string, unknown>;
  if (typeof sig.proof !== "object" || sig.proof === null) return false;
  const proof = sig.proof as Record<string, unknown>;
  return (
    typeof proof.alg === "string"
    && typeof proof.signature === "string"
    && proof.signature.length > 0
    && typeof proof.signer_id === "string"
  );
}

export { PROTOCOL_VERSION };
