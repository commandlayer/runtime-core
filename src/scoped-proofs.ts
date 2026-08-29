import { createHash } from "node:crypto";
import { canonicalize } from "./canonicalize.js";
import { CANONICAL_METHOD, SIGNATURE_ALG, signCanonical } from "./crypto.js";
import {
  buildCoveredPayload,
  SCOPED_PROOF_COVERS,
  type CommandLayerReceipt,
  type CommandLayerScopedProof,
  type ScopedProofType,
} from "./compat.js";

export interface SignScopedProofOptions {
  privateKeyPem: string;
  kid: string;
  signer: string;
}

function requireNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${field} is required`);
  }
  return value;
}

/**
 * Create one fixed-coverage CommandLayer scoped proof.
 *
 * Coverage is chosen by runtime-core from SCOPED_PROOF_COVERS rather than
 * accepted from callers. This prevents execution proofs from accidentally
 * covering settlement fields (or settlement proofs from covering execution).
 */
export function createScopedProof(
  receipt: CommandLayerReceipt,
  type: ScopedProofType,
  options: SignScopedProofOptions,
): CommandLayerScopedProof {
  if (!receipt || typeof receipt !== "object") throw new Error("receipt is required");
  const privateKeyPem = requireNonEmptyString(options?.privateKeyPem, "privateKeyPem");
  const kid = requireNonEmptyString(options?.kid, "kid");
  const signer = requireNonEmptyString(options?.signer, "signer");

  const covers = [...SCOPED_PROOF_COVERS[type]];
  const coveredPayload = buildCoveredPayload(receipt, { type, covers });
  const canonical = canonicalize(coveredPayload);
  const hash = createHash("sha256").update(canonical, "utf8").digest("hex");

  return {
    type,
    covers,
    canonicalization: CANONICAL_METHOD,
    hash: { alg: "SHA-256", value: hash },
    signature: {
      alg: SIGNATURE_ALG,
      value: signCanonical(canonical, privateKeyPem),
      kid,
      signer,
    },
  };
}

/** Append a scoped proof without mutating the input receipt. */
export function appendScopedProof(
  receipt: CommandLayerReceipt,
  proof: CommandLayerScopedProof,
): CommandLayerReceipt {
  if (!receipt || typeof receipt !== "object") throw new Error("receipt is required");
  if (!proof || typeof proof !== "object") throw new Error("proof is required");
  // Re-materialize the covered payload here so malformed/foreign coverage is
  // rejected before the proof enters a receipt assembled by runtime-core.
  buildCoveredPayload(receipt, proof);
  return { ...receipt, proofs: [...(receipt.proofs ?? []), proof] };
}

export function signScopedProof(
  receipt: CommandLayerReceipt,
  type: ScopedProofType,
  options: SignScopedProofOptions,
): CommandLayerReceipt {
  return appendScopedProof(receipt, createScopedProof(receipt, type, options));
}

export function signExecutionScopedProof(
  receipt: CommandLayerReceipt,
  options: SignScopedProofOptions,
): CommandLayerReceipt {
  return signScopedProof(receipt, "execution", options);
}

export function signSettlementScopedProof(
  receipt: CommandLayerReceipt,
  options: SignScopedProofOptions,
): CommandLayerReceipt {
  return signScopedProof(receipt, "settlement", options);
}
