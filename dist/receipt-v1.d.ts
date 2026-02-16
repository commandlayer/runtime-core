/**
 * Receipt v1 engine
 * - canonical = json.sorted_keys.v1
 * - hash = sha256 hex of canonical string
 * - signature = Ed25519 over UTF-8 bytes of the hex hash string
 *
 * Proof fields (recommended):
 *   metadata.proof = {
 *     alg: "ed25519-sha256",
 *     canonical: "json.sorted_keys.v1",
 *     signer_id: "<ens>",
 *     kid: "v1",
 *     hash_sha256: "<hex>",
 *     signature_b64: "<base64>"
 *   }
 *
 * Compat:
 * - verify accepts `signature_b64` OR legacy `signature` (base64url) if present
 */
export type ReceiptStatus = "success" | "error" | "delegated";
export type ReceiptProof = {
    alg: "ed25519-sha256" | string;
    canonical: string;
    signer_id: string;
    kid?: string;
    hash_sha256: string;
    signature_b64?: string;
    signature?: string;
};
export type ReceiptBase = {
    x402: {
        verb: string;
        version: string;
        [k: string]: any;
    };
    trace: {
        trace_id: string;
        [k: string]: any;
    };
    status: ReceiptStatus;
    result?: any;
    error?: any;
    metadata?: {
        proof?: ReceiptProof;
        receipt_id?: string;
        [k: string]: any;
    };
    [k: string]: any;
};
/**
 * Build the "unsigned" view of a receipt used for hashing.
 * We remove fields that must not participate in hashing/signing.
 */
export declare function unsignedReceiptView(receipt: ReceiptBase): any;
/** Compute canonical string + hash for a receipt (unsigned view) */
export declare function computeReceiptCanonicalAndHash(receipt: ReceiptBase): {
    canonical: string;
    hash_sha256: string;
};
export type SignOptions = {
    signer_id: string;
    kid?: string;
    canonical?: string;
    privateKeyPem: string;
};
/**
 * Attach/overwrite metadata.proof + metadata.receipt_id and return a new receipt object.
 */
export declare function signReceiptEd25519Sha256(receipt: ReceiptBase, opts: SignOptions): ReceiptBase;
export type VerifyOptions = {
    publicKeyPemOrDer: string;
    allowedCanonicals?: string[];
    requireKid?: string;
    requireSignerId?: string;
};
/**
 * Verify receipt signature + hash integrity.
 * Returns ok=false with a concrete reason string when failing.
 */
export declare function verifyReceiptEd25519Sha256(receipt: ReceiptBase, opts: VerifyOptions): {
    ok: boolean;
    reason?: string;
};
/**
 * Enforce that a receipt proof.canonical matches what ENS declares for a signer.
 * Use this when you have ENS TXT `cl.sig.canonical`.
 */
export declare function enforceCanonicalFromEns(receipt: ReceiptBase, ensCanonical: string): {
    ok: boolean;
    reason?: string;
};
//# sourceMappingURL=receipt-v1.d.ts.map