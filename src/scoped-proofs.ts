import { canonicalize } from "./canonicalize.js";
import { CANONICAL_METHOD, SIGNATURE_ALG, signCanonical, verifyCanonical } from "./crypto.js";
import { SCOPED_PROOF_COVERS, type ScopedProofType } from "./compat.js";

export interface ClasScopedSignature {
  alg: typeof SIGNATURE_ALG | "ed25519";
  kid: string;
  value: string;
}

/** Strict CLAS `clas.execution.receipt.v1` proof shape. */
export interface ClasScopedProof {
  type: ScopedProofType;
  covers: string[];
  signer: string;
  canonicalization: typeof CANONICAL_METHOD;
  signature: ClasScopedSignature;
}

export interface ClasExecutionReceipt {
  receipt_id: string;
  verb: string;
  agent: unknown;
  action: unknown;
  settlement?: unknown;
  proofs?: ClasScopedProof[];
  [key: string]: unknown;
}

export interface SignScopedProofOptions {
  privateKeyPem: string;
  kid: string;
  signer: string;
}

export interface VerifyClasScopedProofResult {
  type: ScopedProofType;
  signer: string;
  covered: string[];
  signature_valid: boolean;
  ok: boolean;
  errors: string[];
}

export interface VerifyClasScopedProofsResult {
  ok: boolean;
  status: "VERIFIED" | "INVALID";
  proofs: VerifyClasScopedProofResult[];
  errors: string[];
}

export interface VerifyClasScopedProofsOptions {
  publicKeyPemOrDer?: string;
  publicKeysByKid?: Record<string, string>;
  resolvePublicKey?: (proof: ClasScopedProof) => string | undefined;
}

function requireNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${field} is required`);
  }
  return value;
}

function arraysEqual(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function assertProofType(type: unknown): asserts type is ScopedProofType {
  if (type !== "execution" && type !== "settlement") throw new Error("ERR_UNSUPPORTED_PROOF_TYPE");
}

/**
 * Materialize the exact CLAS-covered top-level payload.
 * Coverage is fixed by proof type and cannot be expanded by callers.
 */
export function buildClasScopedPayload(
  receipt: ClasExecutionReceipt,
  proof: Pick<ClasScopedProof, "type" | "covers">,
): Record<string, unknown> {
  if (!receipt || typeof receipt !== "object") throw new Error("ERR_MALFORMED_RECEIPT");
  if (!proof || typeof proof !== "object") throw new Error("ERR_MALFORMED_PROOF");
  assertProofType(proof.type);
  if (!Array.isArray(proof.covers) || !proof.covers.every((field) => typeof field === "string")) {
    throw new Error("ERR_MALFORMED_COVERS");
  }

  const expected = SCOPED_PROOF_COVERS[proof.type];
  if (!arraysEqual(proof.covers, expected)) throw new Error(`ERR_INVALID_${proof.type.toUpperCase()}_COVERS`);

  const source = receipt as Record<string, unknown>;
  const payload: Record<string, unknown> = {};
  for (const field of proof.covers) {
    if (!(field in source) || source[field] === undefined) throw new Error(`ERR_MISSING_COVERED_FIELD:${field}`);
    payload[field] = source[field];
  }
  return payload;
}

/**
 * Create a strict CLAS scoped proof.
 *
 * New proofs intentionally do not include a `hash` field and keep `signer`
 * top-level, matching the canonical CLAS execution receipt schema. Legacy
 * hash-bearing proof verification remains in compat.ts for backwards
 * compatibility; new signing must not emit that legacy shape.
 */
export function createScopedProof(
  receipt: ClasExecutionReceipt,
  type: ScopedProofType,
  options: SignScopedProofOptions,
): ClasScopedProof {
  if (!receipt || typeof receipt !== "object") throw new Error("receipt is required");
  assertProofType(type);
  const privateKeyPem = requireNonEmptyString(options?.privateKeyPem, "privateKeyPem");
  const kid = requireNonEmptyString(options?.kid, "kid");
  const signer = requireNonEmptyString(options?.signer, "signer");
  const covers = [...SCOPED_PROOF_COVERS[type]];
  const canonical = canonicalize(buildClasScopedPayload(receipt, { type, covers }));

  return {
    type,
    covers,
    signer,
    canonicalization: CANONICAL_METHOD,
    signature: {
      alg: SIGNATURE_ALG,
      kid,
      value: signCanonical(canonical, privateKeyPem),
    },
  };
}

/** Append a strict CLAS scoped proof without mutating the input receipt. */
export function appendScopedProof(
  receipt: ClasExecutionReceipt,
  proof: ClasScopedProof,
): ClasExecutionReceipt {
  if (!receipt || typeof receipt !== "object") throw new Error("receipt is required");
  requireNonEmptyString(proof?.signer, "proof.signer");
  buildClasScopedPayload(receipt, proof);
  return { ...receipt, proofs: [...(receipt.proofs ?? []), proof] };
}

export function signScopedProof(
  receipt: ClasExecutionReceipt,
  type: ScopedProofType,
  options: SignScopedProofOptions,
): ClasExecutionReceipt {
  return appendScopedProof(receipt, createScopedProof(receipt, type, options));
}

export function signExecutionScopedProof(
  receipt: ClasExecutionReceipt,
  options: SignScopedProofOptions,
): ClasExecutionReceipt {
  return signScopedProof(receipt, "execution", options);
}

export function signSettlementScopedProof(
  receipt: ClasExecutionReceipt,
  options: SignScopedProofOptions,
): ClasExecutionReceipt {
  return signScopedProof(receipt, "settlement", options);
}

export function verifyClasScopedProof(
  receipt: ClasExecutionReceipt,
  proof: ClasScopedProof,
  options: VerifyClasScopedProofsOptions,
): VerifyClasScopedProofResult {
  const errors: string[] = [];
  const type = proof?.type === "settlement" ? "settlement" : "execution";
  const result: VerifyClasScopedProofResult = {
    type,
    signer: typeof proof?.signer === "string" ? proof.signer : "",
    covered: Array.isArray(proof?.covers) ? [...proof.covers] : [],
    signature_valid: false,
    ok: false,
    errors,
  };

  if (!proof || typeof proof !== "object") errors.push("ERR_MALFORMED_PROOF");
  if (proof?.type !== "execution" && proof?.type !== "settlement") errors.push("ERR_UNSUPPORTED_PROOF_TYPE");
  if (typeof proof?.signer !== "string" || proof.signer.trim().length === 0) errors.push("ERR_MISSING_SIGNER");
  if (proof?.canonicalization !== CANONICAL_METHOD) errors.push("ERR_UNSUPPORTED_CANONICALIZATION");
  if (!proof?.signature || typeof proof.signature !== "object") errors.push("ERR_MISSING_SIGNATURE");
  const signatureAlg = proof?.signature?.alg === "ed25519" ? SIGNATURE_ALG : proof?.signature?.alg;
  if (signatureAlg !== SIGNATURE_ALG) errors.push("ERR_UNSUPPORTED_SIGNATURE_ALG");
  if (typeof proof?.signature?.kid !== "string" || proof.signature.kid.trim().length === 0) errors.push("ERR_MISSING_SIGNATURE_KID");
  if (typeof proof?.signature?.value !== "string" || proof.signature.value.length === 0) errors.push("ERR_MISSING_SIGNATURE_VALUE");

  let canonical = "";
  if (errors.length === 0) {
    try {
      canonical = canonicalize(buildClasScopedPayload(receipt, proof));
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }

  if (errors.length === 0) {
    const key = options.resolvePublicKey?.(proof) ?? options.publicKeysByKid?.[proof.signature.kid] ?? options.publicKeyPemOrDer;
    if (!key) errors.push("ERR_MISSING_PUBLIC_KEY");
    else if (verifyCanonical(canonical, proof.signature.value, key)) result.signature_valid = true;
    else errors.push("ERR_SIGNATURE_INVALID");
  }

  result.ok = errors.length === 0 && result.signature_valid;
  return result;
}

/** Verify the strict canonical CLAS scoped-proof shape. */
export function verifyClasScopedProofs(
  receipt: ClasExecutionReceipt,
  options: VerifyClasScopedProofsOptions,
): VerifyClasScopedProofsResult {
  if (!options.publicKeyPemOrDer && !options.publicKeysByKid && !options.resolvePublicKey) {
    throw new Error("verifyClasScopedProofs requires publicKeyPemOrDer, publicKeysByKid, or resolvePublicKey");
  }

  const errors: string[] = [];
  if (!Array.isArray(receipt?.proofs) || receipt.proofs.length === 0) {
    return { ok: false, status: "INVALID", proofs: [], errors: ["ERR_MISSING_PROOFS"] };
  }

  const proofs = receipt.proofs.map((proof) => verifyClasScopedProof(receipt, proof, options));
  if (!proofs.some((proof) => proof.type === "execution" && proof.ok)) errors.push("ERR_MISSING_EXECUTION_PROOF");
  if (receipt.settlement !== undefined && !proofs.some((proof) => proof.type === "settlement" && proof.ok)) {
    errors.push("ERR_MISSING_SETTLEMENT_PROOF");
  }
  if (receipt.settlement === undefined && receipt.proofs.some((proof) => proof.type === "settlement")) {
    errors.push("ERR_UNEXPECTED_SETTLEMENT_PROOF");
  }

  const ok = proofs.every((proof) => proof.ok) && errors.length === 0;
  return { ok, status: ok ? "VERIFIED" : "INVALID", proofs, errors };
}
