/**
 * CommandLayer Machine-Service Factory execution evidence.
 *
 * Profile: commandlayer.execution-evidence.v1
 *
 * This receipt proves execution integrity/provenance and observed acceptance.
 * It intentionally does NOT prove payment and must not contain settlement data.
 */

import { canonicalize, CANONICAL_METHOD } from "./canonicalize.js";
import {
  SIGNATURE_ALG,
  signCanonical,
  verifyCanonical,
  verifyCanonicalWithRawKey,
} from "./crypto.js";

export const FACTORY_EXECUTION_RECEIPT_PROFILE = "commandlayer.execution-evidence.v1" as const;

export type AcceptanceStatus = "pass" | "fail" | "unknown";

export interface FactoryProviderStep {
  step_id: string;
  kind: string;
  provider: string | null;
  started_at: string | null;
  completed_at: string | null;
  result_hash: string | null;
}

export interface FactoryAcceptanceCheck {
  name: string;
  status: AcceptanceStatus;
  assertion: string | null;
  observed: unknown;
}

export interface FactoryExecutionEvidence {
  execution_id: string;
  service_id: string;
  service_version: string;
  request_fingerprint: string;
  workflow_hash: string | null;
  input_hash: string;
  output_hash: string;
  started_at: string;
  completed_at: string;
  provider_steps: FactoryProviderStep[];
  acceptance_checks: FactoryAcceptanceCheck[];
  observed_state: Record<string, unknown> | null;
}

export interface FactoryExecutionReceipt {
  receipt_id: string;
  profile: typeof FACTORY_EXECUTION_RECEIPT_PROFILE;
  issued_at: string;
  service: {
    service_id: string;
    service_version: string;
  };
  execution: FactoryExecutionEvidence;
}

export interface FactoryExecutionProof {
  alg: typeof SIGNATURE_ALG;
  kid: string;
  signer_id: string;
  canonical: typeof CANONICAL_METHOD;
  signature: string;
}

export interface SignedFactoryExecutionReceipt extends FactoryExecutionReceipt {
  proof: FactoryExecutionProof;
}

export interface SignFactoryExecutionReceiptOptions {
  privateKeyPem: string;
  kid: string;
  signerId: string;
}

/**
 * Input passed to a non-exportable signing backend (KMS/HSM/TEE/etc.).
 * `message` is exactly the UTF-8 bytes of json.sorted_keys.v1 canonicalization.
 * The callback must sign these bytes directly with Ed25519 and return a raw
 * 64-byte signature or its standard-base64 representation.
 */
export interface FactoryExternalSignRequest {
  alg: typeof SIGNATURE_ALG;
  canonical: typeof CANONICAL_METHOD;
  profile: typeof FACTORY_EXECUTION_RECEIPT_PROFILE;
  kid: string;
  signerId: string;
  message: Uint8Array;
}

export type FactoryExternalSignature = Uint8Array | string;

export type FactoryExternalSigner = (
  request: FactoryExternalSignRequest
) => Promise<FactoryExternalSignature> | FactoryExternalSignature;

export interface SignFactoryExecutionReceiptWithSignerOptions {
  kid: string;
  signerId: string;
  sign: FactoryExternalSigner;
}

export interface FactoryVerificationKey {
  publicKeyPem?: string;
  rawPublicKey?: Uint8Array;
  kid?: string;
  signerId?: string;
}

export interface ResolveFactoryVerificationKeyInput {
  kid: string;
  signerId: string;
  alg: typeof SIGNATURE_ALG;
}

export type FactoryVerificationKeyResolver = (
  input: ResolveFactoryVerificationKeyInput
) => Promise<FactoryVerificationKey | null> | FactoryVerificationKey | null;

export interface VerifyFactoryExecutionReceiptOptions {
  expectedSigner?: string;
  expectedKid?: string;
  publicKeyPem?: string;
  rawPublicKey?: Uint8Array;
  resolveKey?: FactoryVerificationKeyResolver;
}

export interface VerifyFactoryExecutionReceiptResult {
  valid: boolean;
  profile: typeof FACTORY_EXECUTION_RECEIPT_PROFILE | null;
  checks: {
    structureValid: boolean;
    profileValid: boolean;
    paymentFieldsAbsent: boolean;
    serviceBindingValid: boolean;
    timeOrderValid: boolean;
    algValid: boolean;
    canonicalValid: boolean;
    kidMatched: boolean;
    signerMatched: boolean;
    signatureValid: boolean;
  };
  signer: {
    kid: string | null;
    signer_id: string | null;
  };
  reason?: string;
}

const SHA256_URI = /^sha256:[a-f0-9]{64}$/i;
const ACCEPTANCE_STATUSES = new Set<AcceptanceStatus>(["pass", "fail", "unknown"]);
const FORBIDDEN_PAYMENT_KEYS = new Set([
  "payment",
  "payment_id",
  "settlement",
  "transaction",
  "tx_hash",
]);

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function validDate(value: unknown): value is string {
  return nonEmpty(value) && Number.isFinite(Date.parse(value));
}

function hashUri(value: unknown): value is string {
  return nonEmpty(value) && SHA256_URI.test(value);
}

function findForbiddenPaymentPaths(value: unknown, path = "receipt", seen = new Set<object>()): string[] {
  if (value === null || typeof value !== "object") return [];
  if (seen.has(value)) return [];
  seen.add(value);

  if (Array.isArray(value)) {
    return value.flatMap((item, index) => findForbiddenPaymentPaths(item, `${path}[${index}]`, seen));
  }

  const found: string[] = [];
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    const child = `${path}.${key}`;
    if (FORBIDDEN_PAYMENT_KEYS.has(key)) found.push(child);
    found.push(...findForbiddenPaymentPaths(nested, child, seen));
  }
  return found;
}

export function assertFactoryExecutionReceipt(receipt: FactoryExecutionReceipt): FactoryExecutionReceipt {
  if (!receipt || typeof receipt !== "object") throw new TypeError("factory execution receipt is required");
  if (!nonEmpty(receipt.receipt_id)) throw new TypeError("receipt_id is required");
  if (receipt.profile !== FACTORY_EXECUTION_RECEIPT_PROFILE) {
    throw new TypeError(`profile must be ${FACTORY_EXECUTION_RECEIPT_PROFILE}`);
  }
  if (!validDate(receipt.issued_at)) throw new TypeError("issued_at must be an ISO date-time");
  if (!receipt.service || typeof receipt.service !== "object") throw new TypeError("service is required");
  const execution = receipt.execution;
  if (!execution || typeof execution !== "object") throw new TypeError("execution is required");

  for (const field of ["execution_id", "service_id", "service_version"] as const) {
    if (!nonEmpty(execution[field])) throw new TypeError(`execution.${field} is required`);
  }
  for (const field of ["request_fingerprint", "input_hash", "output_hash"] as const) {
    if (!hashUri(execution[field])) throw new TypeError(`execution.${field} must be sha256:<64 hex>`);
  }
  if (execution.workflow_hash !== null && !hashUri(execution.workflow_hash)) {
    throw new TypeError("execution.workflow_hash must be null or sha256:<64 hex>");
  }
  if (!validDate(execution.started_at) || !validDate(execution.completed_at)) {
    throw new TypeError("execution timestamps must be ISO date-times");
  }
  if (Date.parse(execution.completed_at) < Date.parse(execution.started_at)) {
    throw new TypeError("execution.completed_at must not precede started_at");
  }
  if (Date.parse(receipt.issued_at) < Date.parse(execution.completed_at)) {
    throw new TypeError("issued_at must not precede execution completion");
  }
  if (receipt.service.service_id !== execution.service_id || receipt.service.service_version !== execution.service_version) {
    throw new TypeError("receipt service identity must match execution service identity");
  }
  if (!Array.isArray(execution.provider_steps)) throw new TypeError("execution.provider_steps must be an array");
  if (!Array.isArray(execution.acceptance_checks)) throw new TypeError("execution.acceptance_checks must be an array");
  for (const [index, check] of execution.acceptance_checks.entries()) {
    if (!check || typeof check !== "object" || !nonEmpty(check.name) || !ACCEPTANCE_STATUSES.has(check.status)) {
      throw new TypeError(`execution.acceptance_checks[${index}] is invalid`);
    }
  }
  if (execution.observed_state !== null && (typeof execution.observed_state !== "object" || Array.isArray(execution.observed_state))) {
    throw new TypeError("execution.observed_state must be an object or null");
  }

  const paymentPaths = findForbiddenPaymentPaths(receipt);
  if (paymentPaths.length > 0) {
    throw new TypeError(`factory execution receipt must not contain payment proof fields: ${paymentPaths.join(", ")}`);
  }
  return receipt;
}

function unsignedReceipt(receipt: SignedFactoryExecutionReceipt): FactoryExecutionReceipt {
  const { proof: _proof, ...unsigned } = receipt;
  return unsigned;
}

function buildSignedFactoryExecutionReceipt(
  receipt: FactoryExecutionReceipt,
  signature: string,
  kid: string,
  signerId: string
): SignedFactoryExecutionReceipt {
  return {
    ...receipt,
    proof: {
      alg: SIGNATURE_ALG,
      kid: kid.trim(),
      signer_id: signerId.trim(),
      canonical: CANONICAL_METHOD,
      signature,
    },
  };
}

function normalizeExternalSignature(signature: FactoryExternalSignature): string {
  let bytes: Buffer;
  if (typeof signature === "string") {
    if (!nonEmpty(signature)) throw new TypeError("external signer returned an empty signature");
    bytes = Buffer.from(signature, "base64");
  } else if (signature instanceof Uint8Array) {
    bytes = Buffer.from(signature);
  } else {
    throw new TypeError("external signer must return a Uint8Array or base64 string");
  }
  if (bytes.length !== 64) {
    throw new TypeError(`external Ed25519 signature must be 64 bytes, got ${bytes.length}`);
  }
  return bytes.toString("base64");
}

export function signFactoryExecutionReceipt(
  receipt: FactoryExecutionReceipt,
  opts: SignFactoryExecutionReceiptOptions
): SignedFactoryExecutionReceipt {
  assertFactoryExecutionReceipt(receipt);
  if (!nonEmpty(opts?.privateKeyPem)) throw new TypeError("privateKeyPem is required");
  if (!nonEmpty(opts?.kid)) throw new TypeError("kid is required");
  if (!nonEmpty(opts?.signerId)) throw new TypeError("signerId is required");

  const signature = signCanonical(canonicalize(receipt), opts.privateKeyPem);
  return buildSignedFactoryExecutionReceipt(receipt, signature, opts.kid, opts.signerId);
}

/**
 * Sign a factory receipt through an external Ed25519 signer without exposing
 * private key material to runtime-core. This is the production KMS/HSM/TEE
 * integration surface. runtime-core owns canonicalization and validates the
 * returned signature shape before constructing the proof envelope.
 */
export async function signFactoryExecutionReceiptWithSigner(
  receipt: FactoryExecutionReceipt,
  opts: SignFactoryExecutionReceiptWithSignerOptions
): Promise<SignedFactoryExecutionReceipt> {
  assertFactoryExecutionReceipt(receipt);
  if (!nonEmpty(opts?.kid)) throw new TypeError("kid is required");
  if (!nonEmpty(opts?.signerId)) throw new TypeError("signerId is required");
  if (typeof opts?.sign !== "function") throw new TypeError("external sign callback is required");

  const canonical = canonicalize(receipt);
  const message = new Uint8Array(Buffer.from(canonical, "utf8"));
  const returned = await opts.sign({
    alg: SIGNATURE_ALG,
    canonical: CANONICAL_METHOD,
    profile: FACTORY_EXECUTION_RECEIPT_PROFILE,
    kid: opts.kid.trim(),
    signerId: opts.signerId.trim(),
    message,
  });
  const signature = normalizeExternalSignature(returned);
  return buildSignedFactoryExecutionReceipt(receipt, signature, opts.kid, opts.signerId);
}

function blankResult(): VerifyFactoryExecutionReceiptResult {
  return {
    valid: false,
    profile: null,
    checks: {
      structureValid: false,
      profileValid: false,
      paymentFieldsAbsent: false,
      serviceBindingValid: false,
      timeOrderValid: false,
      algValid: false,
      canonicalValid: false,
      kidMatched: false,
      signerMatched: false,
      signatureValid: false,
    },
    signer: { kid: null, signer_id: null },
  };
}

export async function verifyFactoryExecutionReceipt(
  signed: SignedFactoryExecutionReceipt,
  opts: VerifyFactoryExecutionReceiptOptions = {}
): Promise<VerifyFactoryExecutionReceiptResult> {
  const result = blankResult();
  if (!signed || typeof signed !== "object" || !signed.proof || typeof signed.proof !== "object") {
    return { ...result, reason: "Receipt is missing proof structure" };
  }

  result.signer = {
    kid: nonEmpty(signed.proof.kid) ? signed.proof.kid : null,
    signer_id: nonEmpty(signed.proof.signer_id) ? signed.proof.signer_id : null,
  };

  const receipt = unsignedReceipt(signed);
  try {
    assertFactoryExecutionReceipt(receipt);
    result.checks.structureValid = true;
    result.checks.profileValid = receipt.profile === FACTORY_EXECUTION_RECEIPT_PROFILE;
    result.profile = result.checks.profileValid ? FACTORY_EXECUTION_RECEIPT_PROFILE : null;
    result.checks.paymentFieldsAbsent = findForbiddenPaymentPaths(receipt).length === 0;
    result.checks.serviceBindingValid = receipt.service.service_id === receipt.execution.service_id
      && receipt.service.service_version === receipt.execution.service_version;
    result.checks.timeOrderValid = Date.parse(receipt.execution.completed_at) >= Date.parse(receipt.execution.started_at)
      && Date.parse(receipt.issued_at) >= Date.parse(receipt.execution.completed_at);
  } catch (error) {
    return { ...result, reason: (error as Error).message };
  }

  result.checks.algValid = signed.proof.alg === SIGNATURE_ALG;
  result.checks.canonicalValid = signed.proof.canonical === CANONICAL_METHOD;
  result.checks.kidMatched = opts.expectedKid ? signed.proof.kid === opts.expectedKid : true;
  result.checks.signerMatched = opts.expectedSigner ? signed.proof.signer_id === opts.expectedSigner : true;

  if (!result.checks.algValid || !result.checks.canonicalValid) {
    return { ...result, reason: "Unsupported proof algorithm or canonicalization method" };
  }

  let key: FactoryVerificationKey = {
    publicKeyPem: opts.publicKeyPem,
    rawPublicKey: opts.rawPublicKey,
  };
  if (!key.publicKeyPem && !key.rawPublicKey && opts.resolveKey) {
    key = (await opts.resolveKey({
      kid: signed.proof.kid,
      signerId: signed.proof.signer_id,
      alg: SIGNATURE_ALG,
    })) || {};
  }
  if (!key.publicKeyPem && !key.rawPublicKey) {
    return { ...result, reason: "No verification key available" };
  }
  if (key.kid && key.kid !== signed.proof.kid) result.checks.kidMatched = false;
  if (key.signerId && key.signerId !== signed.proof.signer_id) result.checks.signerMatched = false;

  try {
    const canonical = canonicalize(receipt);
    result.checks.signatureValid = key.rawPublicKey
      ? verifyCanonicalWithRawKey(canonical, signed.proof.signature, key.rawPublicKey)
      : verifyCanonical(canonical, signed.proof.signature, key.publicKeyPem!);
  } catch (error) {
    return { ...result, reason: `Signature verification error: ${(error as Error).message}` };
  }

  result.valid = Object.values(result.checks).every(Boolean);
  if (!result.valid) {
    result.reason = Object.entries(result.checks)
      .filter(([, value]) => !value)
      .map(([name]) => `${name} failed`)
      .join(", ");
  }
  return result;
}
