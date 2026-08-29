import { canonicalize } from "./canonicalize.js";
import { CANONICAL_METHOD, SIGNATURE_ALG, signCanonical, verifyCanonical } from "./crypto.js";

export const FACTORY_EXECUTION_RECEIPT_PROFILE = "commandlayer.execution-evidence.v1" as const;
export const FACTORY_EXECUTION_PROOF_COVERS = Object.freeze([
  "receipt_id",
  "profile",
  "issued_at",
  "service",
  "execution",
] as const);

export interface FactoryExecutionProofSignature {
  alg: typeof SIGNATURE_ALG;
  kid: string;
  value: string;
}

export interface FactoryExecutionProof {
  type: "execution";
  covers: string[];
  signer: string;
  canonicalization: typeof CANONICAL_METHOD;
  signature: FactoryExecutionProofSignature;
}

export interface FactoryExecutionReceipt {
  receipt_id: string;
  profile: typeof FACTORY_EXECUTION_RECEIPT_PROFILE;
  issued_at: string;
  service: {
    service_id: string;
    service_version: string;
    [key: string]: unknown;
  };
  execution: {
    execution_id: string;
    [key: string]: unknown;
  };
  proof?: FactoryExecutionProof;
  [key: string]: unknown;
}

export interface SignFactoryExecutionReceiptOptions {
  privateKeyPem: string;
  kid: string;
  signer: string;
}

export interface VerifyFactoryExecutionReceiptOptions {
  publicKeyPemOrDer?: string;
  publicKeysByKid?: Record<string, string>;
  resolvePublicKey?: (proof: FactoryExecutionProof) => string | undefined;
}

export interface VerifyFactoryExecutionReceiptResult {
  ok: boolean;
  status: "VERIFIED" | "INVALID";
  signer: string;
  kid: string | null;
  covered: string[];
  signature_valid: boolean;
  errors: string[];
}

const PROOF_FIELDS = Object.freeze(["type", "covers", "signer", "canonicalization", "signature"]);
const SIGNATURE_FIELDS = Object.freeze(["alg", "kid", "value"]);

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function arraysEqual(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function unexpectedKeys(value: unknown, allowed: readonly string[]): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  const allowedSet = new Set(allowed);
  return Object.keys(value as Record<string, unknown>).filter((key) => !allowedSet.has(key));
}

function validateReceiptEnvelope(receipt: FactoryExecutionReceipt): string[] {
  const errors: string[] = [];
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) return ["ERR_MALFORMED_RECEIPT"];
  if (!nonEmpty(receipt.receipt_id)) errors.push("ERR_MISSING_RECEIPT_ID");
  if (receipt.profile !== FACTORY_EXECUTION_RECEIPT_PROFILE) errors.push("ERR_UNSUPPORTED_FACTORY_RECEIPT_PROFILE");
  if (!nonEmpty(receipt.issued_at) || !Number.isFinite(Date.parse(receipt.issued_at))) errors.push("ERR_INVALID_ISSUED_AT");
  if (!receipt.service || typeof receipt.service !== "object" || Array.isArray(receipt.service)) errors.push("ERR_MISSING_SERVICE");
  if (!nonEmpty(receipt.service?.service_id)) errors.push("ERR_MISSING_SERVICE_ID");
  if (!nonEmpty(receipt.service?.service_version)) errors.push("ERR_MISSING_SERVICE_VERSION");
  if (!receipt.execution || typeof receipt.execution !== "object" || Array.isArray(receipt.execution)) errors.push("ERR_MISSING_EXECUTION");
  if (!nonEmpty(receipt.execution?.execution_id)) errors.push("ERR_MISSING_EXECUTION_ID");
  return errors;
}

function validateProofShape(proof: FactoryExecutionProof | undefined): string[] {
  if (!proof || typeof proof !== "object" || Array.isArray(proof)) return ["ERR_MISSING_FACTORY_EXECUTION_PROOF"];
  const errors = unexpectedKeys(proof, PROOF_FIELDS).map((field) => `ERR_UNEXPECTED_PROOF_FIELD:${field}`);
  errors.push(...unexpectedKeys(proof.signature, SIGNATURE_FIELDS).map((field) => `ERR_UNEXPECTED_SIGNATURE_FIELD:${field}`));
  if (proof.type !== "execution") errors.push("ERR_UNSUPPORTED_PROOF_TYPE");
  if (!Array.isArray(proof.covers) || !arraysEqual(proof.covers, FACTORY_EXECUTION_PROOF_COVERS)) errors.push("ERR_INVALID_EXECUTION_COVERS");
  if (!nonEmpty(proof.signer)) errors.push("ERR_MISSING_SIGNER");
  if (proof.canonicalization !== CANONICAL_METHOD) errors.push("ERR_UNSUPPORTED_CANONICALIZATION");
  if (!proof.signature || typeof proof.signature !== "object") errors.push("ERR_MISSING_SIGNATURE");
  if (proof.signature?.alg !== SIGNATURE_ALG) errors.push("ERR_UNSUPPORTED_SIGNATURE_ALG");
  if (!nonEmpty(proof.signature?.kid)) errors.push("ERR_MISSING_SIGNATURE_KID");
  if (!nonEmpty(proof.signature?.value)) errors.push("ERR_MISSING_SIGNATURE_VALUE");
  return errors;
}

/**
 * Materialize the exact rail-neutral execution payload. Identity/payment adapters
 * are intentionally outside this signed scope; only execution evidence and its
 * service envelope are covered.
 */
export function buildFactoryExecutionPayload(receipt: FactoryExecutionReceipt): Record<string, unknown> {
  const errors = validateReceiptEnvelope(receipt);
  if (errors.length > 0) throw new Error(errors[0]);
  return {
    receipt_id: receipt.receipt_id,
    profile: receipt.profile,
    issued_at: receipt.issued_at,
    service: receipt.service,
    execution: receipt.execution,
  };
}

export function createFactoryExecutionProof(
  receipt: FactoryExecutionReceipt,
  options: SignFactoryExecutionReceiptOptions,
): FactoryExecutionProof {
  const privateKeyPem = nonEmpty(options?.privateKeyPem) ? options.privateKeyPem : null;
  const kid = nonEmpty(options?.kid) ? options.kid : null;
  const signer = nonEmpty(options?.signer) ? options.signer : null;
  if (!privateKeyPem) throw new Error("privateKeyPem is required");
  if (!kid) throw new Error("kid is required");
  if (!signer) throw new Error("signer is required");
  const canonical = canonicalize(buildFactoryExecutionPayload(receipt));
  return {
    type: "execution",
    covers: [...FACTORY_EXECUTION_PROOF_COVERS],
    signer,
    canonicalization: CANONICAL_METHOD,
    signature: {
      alg: SIGNATURE_ALG,
      kid,
      value: signCanonical(canonical, privateKeyPem),
    },
  };
}

/** Sign without mutating the input receipt. */
export function signFactoryExecutionReceipt(
  receipt: FactoryExecutionReceipt,
  options: SignFactoryExecutionReceiptOptions,
): FactoryExecutionReceipt {
  return { ...receipt, proof: createFactoryExecutionProof(receipt, options) };
}

export function verifyFactoryExecutionReceipt(
  receipt: FactoryExecutionReceipt,
  options: VerifyFactoryExecutionReceiptOptions,
): VerifyFactoryExecutionReceiptResult {
  const errors = [...validateReceiptEnvelope(receipt), ...validateProofShape(receipt?.proof)];
  const proof = receipt?.proof;
  let signatureValid = false;

  if (errors.length === 0 && proof) {
    const key = options?.resolvePublicKey?.(proof)
      ?? options?.publicKeysByKid?.[proof.signature.kid]
      ?? options?.publicKeyPemOrDer;
    if (!key) {
      errors.push("ERR_MISSING_PUBLIC_KEY");
    } else {
      try {
        const canonical = canonicalize(buildFactoryExecutionPayload(receipt));
        signatureValid = verifyCanonical(canonical, proof.signature.value, key);
        if (!signatureValid) errors.push("ERR_SIGNATURE_INVALID");
      } catch (error) {
        errors.push(error instanceof Error ? error.message : String(error));
      }
    }
  }

  const ok = errors.length === 0 && signatureValid;
  return {
    ok,
    status: ok ? "VERIFIED" : "INVALID",
    signer: proof?.signer ?? "",
    kid: proof?.signature?.kid ?? null,
    covered: Array.isArray(proof?.covers) ? [...proof.covers] : [],
    signature_valid: signatureValid,
    errors,
  };
}
