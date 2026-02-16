import { canonicalizeSortedKeysV1, CANONICAL_ID_SORTED_KEYS_V1 } from "./canonical.js";
import { sha256HexUtf8, signEd25519MessageBase64, verifyEd25519MessageBase64, base64UrlToBase64 } from "./crypto.js";
/**
 * Build the "unsigned" view of a receipt used for hashing.
 * We remove fields that must not participate in hashing/signing.
 */
export function unsignedReceiptView(receipt) {
    const copy = JSON.parse(JSON.stringify(receipt));
    // remove receipt_id
    if (copy?.metadata && typeof copy.metadata === "object") {
        delete copy.metadata.receipt_id;
        if (copy.metadata.proof && typeof copy.metadata.proof === "object") {
            delete copy.metadata.proof.hash_sha256;
            delete copy.metadata.proof.signature_b64;
            delete copy.metadata.proof.signature;
        }
    }
    return copy;
}
/** Compute canonical string + hash for a receipt (unsigned view) */
export function computeReceiptCanonicalAndHash(receipt) {
    const unsigned = unsignedReceiptView(receipt);
    const canonical = canonicalizeSortedKeysV1(unsigned);
    const hash_sha256 = sha256HexUtf8(canonical);
    return { canonical, hash_sha256 };
}
/**
 * Attach/overwrite metadata.proof + metadata.receipt_id and return a new receipt object.
 */
export function signReceiptEd25519Sha256(receipt, opts) {
    const canonicalId = opts.canonical ?? CANONICAL_ID_SORTED_KEYS_V1;
    // We ONLY support json.sorted_keys.v1 in this engine.
    if (canonicalId !== CANONICAL_ID_SORTED_KEYS_V1) {
        throw new Error(`Unsupported canonical '${canonicalId}'. Expected '${CANONICAL_ID_SORTED_KEYS_V1}'.`);
    }
    const { hash_sha256 } = computeReceiptCanonicalAndHash(receipt);
    // Sign the hash *string* bytes (UTF-8), matching current Commons runtime behavior.
    const signature_b64 = signEd25519MessageBase64(hash_sha256, opts.privateKeyPem);
    const next = JSON.parse(JSON.stringify(receipt));
    next.metadata = next.metadata || {};
    const proof = {
        alg: "ed25519-sha256",
        canonical: CANONICAL_ID_SORTED_KEYS_V1,
        signer_id: opts.signer_id,
        ...(opts.kid ? { kid: opts.kid } : {}),
        hash_sha256,
        signature_b64,
    };
    next.metadata.proof = proof;
    next.metadata.receipt_id = hash_sha256; // consistent with your current practice
    return next;
}
/**
 * Verify receipt signature + hash integrity.
 * Returns ok=false with a concrete reason string when failing.
 */
export function verifyReceiptEd25519Sha256(receipt, opts) {
    const proof = receipt?.metadata?.proof;
    if (!proof)
        return { ok: false, reason: "missing_proof" };
    if (opts.requireSignerId && proof.signer_id !== opts.requireSignerId) {
        return { ok: false, reason: "signer_id_mismatch" };
    }
    if (opts.requireKid && proof.kid !== opts.requireKid) {
        return { ok: false, reason: "kid_mismatch" };
    }
    const allowedCanonicals = opts.allowedCanonicals ?? [CANONICAL_ID_SORTED_KEYS_V1];
    if (!allowedCanonicals.includes(proof.canonical)) {
        return { ok: false, reason: "canonical_not_allowed" };
    }
    if (proof.alg !== "ed25519-sha256") {
        return { ok: false, reason: "unsupported_alg" };
    }
    const { hash_sha256 } = computeReceiptCanonicalAndHash(receipt);
    if (typeof proof.hash_sha256 !== "string" || proof.hash_sha256.length !== 64) {
        return { ok: false, reason: "missing_or_invalid_hash" };
    }
    if (hash_sha256 !== proof.hash_sha256) {
        return { ok: false, reason: "hash_mismatch" };
    }
    // Prefer signature_b64. Fall back to legacy base64url `signature`.
    let sigB64 = null;
    if (typeof proof.signature_b64 === "string" && proof.signature_b64.length > 0) {
        sigB64 = proof.signature_b64;
    }
    else if (typeof proof.signature === "string" && proof.signature.length > 0) {
        sigB64 = base64UrlToBase64(proof.signature);
    }
    if (!sigB64)
        return { ok: false, reason: "missing_signature" };
    const ok = verifyEd25519MessageBase64(hash_sha256, sigB64, opts.publicKeyPemOrDer);
    return ok ? { ok: true } : { ok: false, reason: "bad_signature" };
}
/**
 * Enforce that a receipt proof.canonical matches what ENS declares for a signer.
 * Use this when you have ENS TXT `cl.sig.canonical`.
 */
export function enforceCanonicalFromEns(receipt, ensCanonical) {
    const proof = receipt?.metadata?.proof;
    if (!proof)
        return { ok: false, reason: "missing_proof" };
    if (!ensCanonical)
        return { ok: false, reason: "missing_ens_canonical" };
    if (proof.canonical !== ensCanonical)
        return { ok: false, reason: "canonical_mismatch_ens" };
    return { ok: true };
}
//# sourceMappingURL=receipt-v1.js.map