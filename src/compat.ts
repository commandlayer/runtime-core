import { createHash } from "node:crypto";
import { canonicalize } from "./canonicalize.js";
import { signCanonical, verifyCanonical, CANONICAL_METHOD, SIGNATURE_ALG } from "./crypto.js";

export interface EnsVerificationRecord {
  signer: string;
  kid: string;
  canonical: string;
}

export interface VerifyCommandLayerReceiptResult {
  ok: boolean;
  status: "VERIFIED" | "INVALID";
  checks: {
    schema: boolean;
    canonical_hash: boolean;
    signature: boolean;
    signer: boolean;
  };
  errors: string[];
}

export type ScopedProofType = "execution" | "settlement";

export interface CommandLayerScopedProof {
  type: string;
  covers: string[];
  canonicalization: string;
  hash: { alg: "SHA-256"; value: string };
  signature: CommandLayerProofSignature & { signer?: string; signer_id?: string };
}

export interface VerifyScopedProofResult {
  type: string;
  signer?: string;
  covered: string[];
  signature_valid: boolean;
  hash_matches: boolean;
  ok: boolean;
  errors: string[];
}

export interface VerifyScopedProofsResult {
  ok: boolean;
  status: "VERIFIED" | "INVALID";
  proofs: VerifyScopedProofResult[];
  errors: string[];
}

export interface VerifyScopedProofsOptions {
  /** PEM public key used for every proof when proofs share a key. */
  publicKeyPemOrDer?: string;
  /** PEM public keys by signature kid for receipts with multiple signers. */
  publicKeysByKid?: Record<string, string>;
  /** Optional public key resolver for custom key lookup. It must not perform network calls in core primitives. */
  resolvePublicKey?: (proof: CommandLayerScopedProof) => string | undefined;
}

export interface CommandLayerReceipt {
  verb: string;
  version?: string;
  agent?: string;
  timestamp?: string;
  metadata?: {
    proof?: CommandLayerProof;
    [key: string]: unknown;
  };
  proofs?: CommandLayerScopedProof[];
  [key: string]: unknown;
}

export interface CommandLayerProof {
  canonicalization: string;
  hash: { alg: "SHA-256"; value: string };
  signature: CommandLayerProofSignatureField;
}

export type CommandLayerProofSignature = {
  alg: typeof SIGNATURE_ALG | "ed25519";
  value: string;
  kid: string;
};

export type CommandLayerProofSignatureRole =
  | "user"
  | "solver"
  | "relayer"
  | "agent"
  | "runtime"
  | "verifier";

export type CommandLayerProofSignatureWithRole = CommandLayerProofSignature & {
  role: CommandLayerProofSignatureRole;
};

export type CommandLayerProofSignatureField =
  | CommandLayerProofSignature
  | CommandLayerProofSignatureWithRole[];

function isSignatureRole(value: unknown): value is CommandLayerProofSignatureRole {
  return value === "user"
    || value === "solver"
    || value === "relayer"
    || value === "agent"
    || value === "runtime"
    || value === "verifier";
}

export function isSingleSignature(signature: unknown): signature is CommandLayerProofSignature {
  if (!signature || typeof signature !== "object" || Array.isArray(signature)) return false;
  const s = signature as Record<string, unknown>;
  return typeof s.alg === "string" && typeof s.value === "string" && typeof s.kid === "string";
}

export function isMultiSignature(signature: unknown): signature is CommandLayerProofSignatureWithRole[] {
  if (!Array.isArray(signature) || signature.length === 0) return false;
  return signature.every((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
    const s = entry as Record<string, unknown>;
    return typeof s.alg === "string"
      && typeof s.value === "string"
      && typeof s.kid === "string"
      && isSignatureRole(s.role);
  });
}

export function getPrimarySignature(
  proof: CommandLayerProof,
  preferredRole?: CommandLayerProofSignatureRole
): { signature?: CommandLayerProofSignature; error?: string } {
  if (isSingleSignature(proof.signature)) return { signature: proof.signature };
  if (!Array.isArray(proof.signature)) return { error: "ERR_MALFORMED_SIGNATURE" };
  if (!isMultiSignature(proof.signature)) return { error: "ERR_MALFORMED_SIGNATURE_ARRAY" };

  const priority: CommandLayerProofSignatureRole[] = preferredRole
    ? [preferredRole, "runtime", "agent", "verifier"]
    : ["runtime", "agent", "verifier"];

  for (const role of priority) {
    const match = proof.signature.find((s) => s.role === role);
    if (match) return { signature: match };
  }
  return { signature: proof.signature[0] };
}

export function buildCanonicalProof(receipt: CommandLayerReceipt): string {
  const { metadata: meta = {}, ...rest } = receipt;
  const { proof: _proof, ...metaWithoutProof } = meta;
  const payload: Record<string, unknown> = { ...rest, metadata: metaWithoutProof };
  if (Object.keys(metaWithoutProof).length === 0) delete payload.metadata;
  return canonicalize(payload);
}

export const SCOPED_PROOF_COVERS: Record<ScopedProofType, readonly string[]> = {
  execution: ["receipt_id", "verb", "agent", "action"],
  settlement: ["receipt_id", "settlement"],
} as const;

function isSupportedScopedProofType(type: string): type is ScopedProofType {
  return type === "execution" || type === "settlement";
}

function arraysEqual(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

export function buildCoveredPayload(
  receipt: CommandLayerReceipt,
  proof: Pick<CommandLayerScopedProof, "type" | "covers">
): Record<string, unknown> {
  if (!proof || typeof proof !== "object") throw new Error("ERR_MALFORMED_PROOF");
  if (typeof proof.type !== "string" || !isSupportedScopedProofType(proof.type)) {
    throw new Error("ERR_UNSUPPORTED_PROOF_TYPE");
  }
  if (!Array.isArray(proof.covers) || !proof.covers.every((field) => typeof field === "string")) {
    throw new Error("ERR_MALFORMED_COVERS");
  }
  const expected = SCOPED_PROOF_COVERS[proof.type];
  if (!arraysEqual(proof.covers, expected)) {
    throw new Error(`ERR_INVALID_${proof.type.toUpperCase()}_COVERS`);
  }

  const source = receipt as Record<string, unknown>;
  const payload: Record<string, unknown> = {};
  for (const field of proof.covers) {
    if (!(field in source) || source[field] === undefined) {
      throw new Error(`ERR_MISSING_COVERED_FIELD:${field}`);
    }
    payload[field] = source[field];
  }
  return payload;
}

function getScopedProofSigner(proof: CommandLayerScopedProof): string | undefined {
  return proof.signature.signer ?? proof.signature.signer_id;
}

export function verifyScopedProof(
  receipt: CommandLayerReceipt,
  proof: CommandLayerScopedProof,
  opts: VerifyScopedProofsOptions
): VerifyScopedProofResult {
  const errors: string[] = [];
  const covered = Array.isArray(proof?.covers) ? [...proof.covers] : [];
  const result: VerifyScopedProofResult = {
    type: typeof proof?.type === "string" ? proof.type : "",
    signer: proof ? getScopedProofSigner(proof) : undefined,
    covered,
    signature_valid: false,
    hash_matches: false,
    ok: false,
    errors,
  };

  if (!proof || typeof proof !== "object") errors.push("ERR_MALFORMED_PROOF");
  if (typeof proof?.canonicalization !== "string" || proof.canonicalization !== CANONICAL_METHOD) errors.push("ERR_UNSUPPORTED_CANONICALIZATION");
  if (proof?.hash?.alg !== "SHA-256") errors.push("ERR_UNSUPPORTED_HASH_ALG");
  if (typeof proof?.hash?.value !== "string" || !/^[0-9a-f]+$/.test(proof.hash.value)) errors.push("ERR_MISSING_HASH_VALUE");
  if (!proof?.signature || typeof proof.signature !== "object") errors.push("ERR_MISSING_SIGNATURE");
  const signatureAlg = proof?.signature?.alg === "ed25519" ? SIGNATURE_ALG : proof?.signature?.alg;
  if (signatureAlg !== SIGNATURE_ALG) errors.push("ERR_UNSUPPORTED_SIGNATURE_ALG");
  if (typeof proof?.signature?.value !== "string" || proof.signature.value.length === 0) errors.push("ERR_MISSING_SIGNATURE_VALUE");
  if (typeof proof?.signature?.kid !== "string" || proof.signature.kid.trim().length === 0) errors.push("ERR_MISSING_SIGNATURE_KID");

  let canonical = "";
  if (errors.length === 0) {
    try {
      canonical = canonicalize(buildCoveredPayload(receipt, proof));
    } catch (err) {
      errors.push((err as Error).message);
    }
  }

  if (errors.length === 0) {
    const recomputed = createHash("sha256").update(canonical, "utf8").digest("hex");
    result.hash_matches = recomputed === proof.hash.value;
    if (!result.hash_matches) errors.push("ERR_HASH_MISMATCH");
  }

  if (errors.length === 0) {
    const key = opts.resolvePublicKey?.(proof) ?? opts.publicKeysByKid?.[proof.signature.kid] ?? opts.publicKeyPemOrDer;
    if (!key) {
      errors.push("ERR_MISSING_PUBLIC_KEY");
    } else if (verifyCanonical(canonical, proof.signature.value, key)) {
      result.signature_valid = true;
    } else {
      errors.push("ERR_SIGNATURE_INVALID");
    }
  }

  result.ok = errors.length === 0 && result.hash_matches && result.signature_valid;
  return result;
}

export function verifyScopedProofs(
  receipt: CommandLayerReceipt,
  opts: VerifyScopedProofsOptions
): VerifyScopedProofsResult {
  const errors: string[] = [];
  if (!opts.publicKeyPemOrDer && !opts.publicKeysByKid && !opts.resolvePublicKey) {
    throw new Error("verifyScopedProofs requires publicKeyPemOrDer, publicKeysByKid, or resolvePublicKey");
  }
  if (!Array.isArray(receipt.proofs) || receipt.proofs.length === 0) {
    errors.push("ERR_MISSING_PROOFS");
    return { ok: false, status: "INVALID", proofs: [], errors };
  }

  const proofs = receipt.proofs.map((proof) => verifyScopedProof(receipt, proof, opts));
  if (receipt.settlement !== undefined && !proofs.some((proof) => proof.type === "settlement" && proof.ok)) {
    errors.push("ERR_MISSING_SETTLEMENT_PROOF");
  }

  const ok = proofs.every((proof) => proof.ok) && errors.length === 0;
  return { ok, status: ok ? "VERIFIED" : "INVALID", proofs, errors };
}

export function signCommandLayerReceipt(
  receipt: CommandLayerReceipt,
  opts: { privateKeyPem: string; kid: string }
): CommandLayerReceipt {
  if (!opts.privateKeyPem) throw new Error("privateKeyPem is required");
  if (!opts.kid || typeof opts.kid !== "string") throw new Error("kid is required");

  const canonical = buildCanonicalProof(receipt);
  const hash = createHash("sha256").update(canonical, "utf8").digest("hex");
  const sig = signCanonical(canonical, opts.privateKeyPem);

  const { metadata: meta = {}, ...rest } = receipt;
  const { proof: _proof, ...metaWithoutProof } = meta;

  return {
    ...rest,
    metadata: {
      ...metaWithoutProof,
      proof: {
        canonicalization: CANONICAL_METHOD,
        hash: { alg: "SHA-256", value: hash },
        signature: { alg: SIGNATURE_ALG, value: sig, kid: opts.kid },
      },
    },
  };
}

export function verifyCommandLayerReceipt(
  receipt: CommandLayerReceipt,
  opts: {
    publicKeyPemOrDer: string;
    allowedCanonicals?: string[];
    ensRecord?: EnsVerificationRecord;
  }
): VerifyCommandLayerReceiptResult {
  const checks: VerifyCommandLayerReceiptResult["checks"] = {
    schema: false,
    canonical_hash: false,
    signature: false,
    signer: opts.ensRecord ? false : true,
  };
  const errors: string[] = [];

  const proof = receipt?.metadata?.proof;
  if (!proof || typeof proof !== "object") {
    errors.push("ERR_MISSING_PROOF");
    return { ok: false, status: "INVALID", checks, errors };
  }

  if (typeof proof.canonicalization !== "string" || proof.canonicalization.length === 0) {
    errors.push("ERR_MISSING_CANONICALIZATION");
  }
  if (typeof proof.hash?.alg !== "string" || proof.hash.alg.length === 0) {
    errors.push("ERR_MISSING_HASH_ALG");
  }
  if (typeof proof.hash?.value !== "string" || proof.hash.value.length === 0) {
    errors.push("ERR_MISSING_HASH_VALUE");
  }
  const primarySignatureResult = getPrimarySignature(proof as CommandLayerProof);
  const selectedSignature = primarySignatureResult.signature;

  if (primarySignatureResult.error) {
    errors.push(primarySignatureResult.error);
  }
  if (!selectedSignature) {
    errors.push("ERR_MISSING_SIGNATURE");
  }
  if (typeof selectedSignature?.alg !== "string" || selectedSignature.alg.length === 0) {
    errors.push("ERR_MISSING_SIGNATURE_ALG");
  }
  if (typeof selectedSignature?.value !== "string" || selectedSignature.value.length === 0) {
    errors.push("ERR_MISSING_SIGNATURE_VALUE");
  }
  if (typeof selectedSignature?.kid !== "string" || selectedSignature.kid.trim().length === 0) {
    errors.push("ERR_MISSING_SIGNATURE_KID");
  }

  const allowed = opts.allowedCanonicals ?? [CANONICAL_METHOD, "erc8211.composable.v1"];
  if (typeof proof.canonicalization === "string" && !allowed.includes(proof.canonicalization)) {
    errors.push("ERR_UNSUPPORTED_CANONICALIZATION");
  }
  if (proof.hash?.alg && proof.hash.alg !== "SHA-256") {
    errors.push("ERR_UNSUPPORTED_HASH_ALG");
  }
  const signatureAlg = selectedSignature?.alg === "ed25519"
    ? SIGNATURE_ALG
    : selectedSignature?.alg;
  if (signatureAlg && signatureAlg !== SIGNATURE_ALG) {
    errors.push("ERR_UNSUPPORTED_SIGNATURE_ALG");
  }

  if (opts.ensRecord) {
    if (selectedSignature?.kid !== opts.ensRecord.kid) {
      errors.push("ERR_ENS_KID_MISMATCH");
    }
    if (proof.canonicalization !== opts.ensRecord.canonical) {
      errors.push("ERR_ENS_CANONICAL_MISMATCH");
    }
    if (receipt.agent !== opts.ensRecord.signer) {
      errors.push("ERR_ENS_SIGNER_MISMATCH");
    }
  }

  checks.schema = errors.length === 0;

  let canonical = "";
  if (checks.schema) {
    if (proof.canonicalization === "erc8211.composable.v1") {
      // ERC-8211 composable execution canonicalization recognized.
      // Merkle authorization verification is deferred pending the companion Merkle authorization ERC.
      errors.push("ERR_MERKLE_AUTHORIZATION_DEFERRED");
      return { ok: false, status: "INVALID", checks, errors };
    }
    canonical = buildCanonicalProof(receipt);
    const recomputed = createHash("sha256").update(canonical, "utf8").digest("hex");
    if (recomputed === proof.hash.value) {
      checks.canonical_hash = true;
    } else {
      errors.push("ERR_HASH_MISMATCH");
    }

    const sigOk = verifyCanonical(canonical, selectedSignature!.value, opts.publicKeyPemOrDer);
    if (sigOk) {
      checks.signature = true;
    } else {
      errors.push("ERR_SIGNATURE_INVALID");
    }
  }

  if (opts.ensRecord) {
    checks.signer = !errors.some((e) => e.startsWith("ERR_ENS_"));
  }

  const ok = checks.schema && checks.canonical_hash && checks.signature && checks.signer;
  return {
    ok,
    status: ok ? "VERIFIED" : "INVALID",
    checks,
    errors,
  };
}

export function isSignedCommandLayerReceipt(value: unknown): value is CommandLayerReceipt {
  const v = value as CommandLayerReceipt;
  const signature = v?.metadata?.proof?.signature;
  const hasValidSignature = isSingleSignature(signature)
    || (Array.isArray(signature) && isMultiSignature(signature));
  return !!v?.metadata?.proof?.hash?.alg
    && !!v?.metadata?.proof?.hash?.value
    && hasValidSignature;
}
