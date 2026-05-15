import { createHash } from "node:crypto";
import { canonicalize } from "./canonicalize.js";
import { signCanonical, verifyCanonical, CANONICAL_METHOD, SIGNATURE_ALG } from "./crypto.js";

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
  hash: { alg: "sha256"; value: string };
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
  if (!opts.kid) throw new Error("kid is required");

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
        hash: { alg: "sha256", value: hash },
        signature: { alg: SIGNATURE_ALG, value: sig, kid: opts.kid },
      },
    },
  };
}

export function verifyCommandLayerReceipt(
  receipt: CommandLayerReceipt,
  opts: { publicKeyPemOrDer: string; allowedCanonicals?: string[] }
): { ok: boolean; reason?: string } {
  const proof = receipt?.metadata?.proof;
  if (!proof) return { ok: false, reason: "Missing metadata.proof" };
  if (!proof.hash?.alg) return { ok: false, reason: "Missing metadata.proof.hash.alg" };
  if (!proof.hash?.value) return { ok: false, reason: "Missing metadata.proof.hash.value" };
  if (!proof.signature?.alg) return { ok: false, reason: "Missing metadata.proof.signature.alg" };
  if (!proof.signature?.value) return { ok: false, reason: "Missing metadata.proof.signature.value" };

  const allowed = opts.allowedCanonicals ?? [CANONICAL_METHOD];
  if (!allowed.includes(proof.canonicalization)) return { ok: false, reason: "Unsupported canonicalization" };
  if (proof.hash.alg !== "sha256") return { ok: false, reason: "Unsupported hash algorithm" };
  if (proof.signature.alg !== SIGNATURE_ALG) return { ok: false, reason: "Unsupported signature algorithm" };

  const canonical = buildCanonicalProof(receipt);
  const recomputed = createHash("sha256").update(canonical, "utf8").digest("hex");
  if (recomputed !== proof.hash.value) return { ok: false, reason: "Hash mismatch" };

  const ok = verifyCanonical(canonical, proof.signature.value, opts.publicKeyPemOrDer);
  return ok ? { ok: true } : { ok: false, reason: "signature invalid" };
}

export function isSignedCommandLayerReceipt(value: unknown): value is CommandLayerReceipt {
  const v = value as CommandLayerReceipt;
  return !!v?.metadata?.proof?.hash?.alg
    && !!v?.metadata?.proof?.hash?.value
    && !!v?.metadata?.proof?.signature?.alg
    && !!v?.metadata?.proof?.signature?.value;
}
