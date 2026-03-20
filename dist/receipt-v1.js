import { canonicalizeSortedKeysV1, CANONICAL_ID_SORTED_KEYS_V1 } from './canonical.js';
import { sha256HexUtf8, signEd25519MessageBase64, verifyEd25519MessageBase64, base64UrlToBase64 } from './crypto.js';
function clone(value) {
    return JSON.parse(JSON.stringify(value));
}
/** Build the canonical Commons receipt view used for hashing. */
export function buildCanonicalReceipt(receipt) {
    return clone(receipt);
}
/** Compute canonical string + hash for the canonical Commons receipt. */
export function computeReceiptCanonicalAndHash(receipt) {
    const canonicalReceipt = buildCanonicalReceipt(receipt);
    const canonical = canonicalizeSortedKeysV1(canonicalReceipt);
    const hash_sha256 = sha256HexUtf8(canonical);
    return { canonical, hash_sha256 };
}
/** Attach a signature layer while preserving receipt/runtime separation. */
export function signReceiptEd25519Sha256(receipt, opts) {
    const canonicalId = opts.canonical ?? CANONICAL_ID_SORTED_KEYS_V1;
    if (canonicalId !== CANONICAL_ID_SORTED_KEYS_V1) {
        throw new Error(`Unsupported canonical '${canonicalId}'. Expected '${CANONICAL_ID_SORTED_KEYS_V1}'.`);
    }
    const { hash_sha256 } = computeReceiptCanonicalAndHash(receipt);
    const signature_b64 = signEd25519MessageBase64(hash_sha256, opts.privateKeyPem);
    const proof = {
        alg: 'ed25519-sha256',
        canonical: CANONICAL_ID_SORTED_KEYS_V1,
        signer_id: opts.signer_id,
        ...(opts.kid ? { kid: opts.kid } : {}),
        hash_sha256,
        signature_b64
    };
    return {
        receipt: buildCanonicalReceipt(receipt),
        signature: {
            proof,
            receipt_id: hash_sha256
        }
    };
}
function toLayeredReceiptV1(receipt) {
    const layeredReceipt = receipt;
    if (layeredReceipt.receipt) {
        return layeredReceipt;
    }
    const legacyReceipt = buildCanonicalReceipt(receipt);
    const metadata = legacyReceipt.metadata;
    if (metadata) {
        delete legacyReceipt.metadata;
    }
    return {
        receipt: legacyReceipt,
        ...(metadata?.proof
            ? {
                signature: {
                    proof: metadata.proof,
                    ...(typeof metadata.receipt_id === 'string' ? { receipt_id: metadata.receipt_id } : {})
                }
            }
            : {})
    };
}
/** Verify receipt signature + hash integrity over the canonical Commons receipt only. */
export function verifyReceiptEd25519Sha256(receipt, opts) {
    const layeredReceipt = toLayeredReceiptV1(receipt);
    const proof = layeredReceipt.signature?.proof;
    if (!proof)
        return { ok: false, reason: 'missing_proof', checks: { hash_matches: false, signature_matches: false } };
    if (opts.requireSignerId && proof.signer_id !== opts.requireSignerId) {
        return { ok: false, reason: 'signer_id_mismatch', checks: { hash_matches: false, signature_matches: false } };
    }
    if (opts.requireKid && proof.kid !== opts.requireKid) {
        return { ok: false, reason: 'kid_mismatch', checks: { hash_matches: false, signature_matches: false } };
    }
    const allowedCanonicals = opts.allowedCanonicals ?? [CANONICAL_ID_SORTED_KEYS_V1];
    if (!allowedCanonicals.includes(proof.canonical)) {
        return { ok: false, reason: 'canonical_not_allowed', checks: { hash_matches: false, signature_matches: false } };
    }
    if (proof.alg !== 'ed25519-sha256') {
        return { ok: false, reason: 'unsupported_alg', checks: { hash_matches: false, signature_matches: false } };
    }
    const { hash_sha256 } = computeReceiptCanonicalAndHash(layeredReceipt.receipt);
    if (typeof proof.hash_sha256 !== 'string' || proof.hash_sha256.length !== 64) {
        return { ok: false, reason: 'missing_or_invalid_hash', checks: { hash_matches: false, signature_matches: false } };
    }
    if (hash_sha256 !== proof.hash_sha256) {
        return { ok: false, reason: 'hash_mismatch', checks: { hash_matches: false, signature_matches: false } };
    }
    let sigB64 = null;
    if (typeof proof.signature_b64 === 'string' && proof.signature_b64.length > 0) {
        sigB64 = proof.signature_b64;
    }
    else if (typeof proof.signature === 'string' && proof.signature.length > 0) {
        sigB64 = base64UrlToBase64(proof.signature);
    }
    if (!sigB64)
        return { ok: false, reason: 'missing_signature', checks: { hash_matches: true, signature_matches: false } };
    const ok = verifyEd25519MessageBase64(hash_sha256, sigB64, opts.publicKeyPemOrDer);
    return ok
        ? { ok: true, checks: { hash_matches: true, signature_matches: true } }
        : { ok: false, reason: 'bad_signature', checks: { hash_matches: true, signature_matches: false } };
}
export function enforceCanonicalFromEns(layeredReceipt, ensCanonical) {
    const proof = layeredReceipt.signature?.proof;
    if (!proof)
        return { ok: false, reason: 'missing_proof' };
    if (!ensCanonical)
        return { ok: false, reason: 'missing_ens_canonical' };
    if (proof.canonical !== ensCanonical)
        return { ok: false, reason: 'canonical_mismatch_ens' };
    return { ok: true };
}
/** @deprecated Compatibility bridge for callers that still expect metadata.proof on the receipt object. */
export function toLegacyReceiptEnvelope(layeredReceipt) {
    const legacyReceipt = buildCanonicalReceipt(layeredReceipt.receipt);
    const metadata = {
        ...(layeredReceipt.runtime ?? {})
    };
    if (layeredReceipt.signature) {
        metadata.proof = layeredReceipt.signature.proof;
        if (layeredReceipt.signature.receipt_id) {
            metadata.receipt_id = layeredReceipt.signature.receipt_id;
        }
    }
    if (Object.keys(metadata).length > 0) {
        legacyReceipt.metadata = metadata;
    }
    return legacyReceipt;
}
//# sourceMappingURL=receipt-v1.js.map