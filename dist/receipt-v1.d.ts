/**
 * Legacy v1 signing engine.
 * The canonical Commons receipt remains the signing payload.
 * Proof and runtime identifiers are layered outside that receipt.
 */
export type ReceiptStatus = 'success' | 'error' | 'delegated';
export type ReceiptProof = {
    alg: 'ed25519-sha256' | string;
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
    [k: string]: any;
};
export type ReceiptSignatureLayer = {
    proof: ReceiptProof;
    receipt_id?: string;
};
export type LayeredReceiptV1 = {
    receipt: ReceiptBase;
    runtime?: Record<string, unknown>;
    signature?: ReceiptSignatureLayer;
};
/** Build the canonical Commons receipt view used for hashing. */
export declare function buildCanonicalReceipt(receipt: ReceiptBase): ReceiptBase;
/** Compute canonical string + hash for the canonical Commons receipt. */
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
/** Attach a signature layer while preserving receipt/runtime separation. */
export declare function signReceiptEd25519Sha256(receipt: ReceiptBase, opts: SignOptions): LayeredReceiptV1;
export type VerifyOptions = {
    publicKeyPemOrDer: string;
    allowedCanonicals?: string[];
    requireKid?: string;
    requireSignerId?: string;
};
export type VerifyReceiptChecks = {
    hash_matches: boolean;
    signature_matches: boolean;
};
export type VerifyReceiptResult = {
    ok: boolean;
    reason?: string;
    checks: VerifyReceiptChecks;
};
/** Verify receipt signature + hash integrity over the canonical Commons receipt only. */
export declare function verifyReceiptEd25519Sha256(receipt: LayeredReceiptV1 | ReceiptBase, opts: VerifyOptions): VerifyReceiptResult;
export declare function enforceCanonicalFromEns(layeredReceipt: LayeredReceiptV1, ensCanonical: string): {
    ok: boolean;
    reason?: string;
};
/** @deprecated Compatibility bridge for callers that still expect metadata.proof on the receipt object. */
export declare function toLegacyReceiptEnvelope(layeredReceipt: LayeredReceiptV1): ReceiptBase;
//# sourceMappingURL=receipt-v1.d.ts.map