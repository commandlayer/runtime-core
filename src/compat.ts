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

export interface CommandLayerReceipt {
  verb: string;
  version?: string;
  agent?: string;
  timestamp?: string;
  metadata?: {
    proof?: CommandLayerProof;
    [key: string]: unknown;
  };
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

  const allowed = opts.allowedCanonicals ?? [CANONICAL_METHOD, "erc8211.merkle.v1"];
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
    if (proof.canonicalization === "erc8211.merkle.v1") {
      errors.push("ERR_UNSUPPORTED_MERKLE_VERIFICATION");
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
