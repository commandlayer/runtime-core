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
  signature: { alg: typeof SIGNATURE_ALG; value: string; kid: string };
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
  if (typeof proof.signature?.alg !== "string" || proof.signature.alg.length === 0) {
    errors.push("ERR_MISSING_SIGNATURE_ALG");
  }
  if (typeof proof.signature?.value !== "string" || proof.signature.value.length === 0) {
    errors.push("ERR_MISSING_SIGNATURE_VALUE");
  }
  if (typeof proof.signature?.kid !== "string" || proof.signature.kid.trim().length === 0) {
    errors.push("ERR_MISSING_SIGNATURE_KID");
  }

  const allowed = opts.allowedCanonicals ?? [CANONICAL_METHOD];
  if (typeof proof.canonicalization === "string" && !allowed.includes(proof.canonicalization)) {
    errors.push("ERR_UNSUPPORTED_CANONICALIZATION");
  }
  if (proof.hash?.alg && proof.hash.alg !== "SHA-256") {
    errors.push("ERR_UNSUPPORTED_HASH_ALG");
  }
  if (proof.signature?.alg && proof.signature.alg !== SIGNATURE_ALG) {
    errors.push("ERR_UNSUPPORTED_SIGNATURE_ALG");
  }

  if (opts.ensRecord) {
    if (proof.signature?.kid !== opts.ensRecord.kid) {
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
    canonical = buildCanonicalProof(receipt);
    const recomputed = createHash("sha256").update(canonical, "utf8").digest("hex");
    if (recomputed === proof.hash.value) {
      checks.canonical_hash = true;
    } else {
      errors.push("ERR_HASH_MISMATCH");
    }

    const sigOk = verifyCanonical(canonical, proof.signature.value, opts.publicKeyPemOrDer);
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
  return !!v?.metadata?.proof?.hash?.alg
    && !!v?.metadata?.proof?.hash?.value
    && !!v?.metadata?.proof?.signature?.alg
    && !!v?.metadata?.proof?.signature?.value
    && !!v?.metadata?.proof?.signature?.kid;
}
