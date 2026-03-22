/**
 * Legacy 1.0.0 receipt verification bridge.
 * Kept only for consumers still reading metadata.proof or hash-bound ed25519-sha256 receipts.
 */
export type LegacyReceiptStatus = 'success' | 'error' | 'delegated';
export type ReceiptProof = {
    alg: 'ed25519-sha256' | string;
    canonical: string;
    signer_id: string;
    kid?: string;
    hash_sha256: string;
    signature_b64?: string;
    signature?: string;
};
export type LegacyReceiptBase = {
    verb?: string;
    version?: string;
    x402?: {
        [k: string]: any;
    };
    trace?: {
        [k: string]: any;
    };
    payload?: any;
    status: LegacyReceiptStatus;
    result?: any;
    error?: any;
    metadata?: Record<string, unknown> & {
        proof?: ReceiptProof;
        receipt_id?: string;
    };
    [k: string]: any;
};
export type ReceiptSignatureLayer = {
    proof: ReceiptProof;
    receipt_id?: string;
};
export type LayeredReceiptV1 = {
    receipt: Omit<LegacyReceiptBase, 'metadata'>;
    runtime?: Record<string, unknown>;
    signature?: ReceiptSignatureLayer;
};
export declare function buildCanonicalReceipt(receipt: Omit<LegacyReceiptBase, 'metadata'>): Omit<LegacyReceiptBase, 'metadata'>;
export declare function computeReceiptCanonicalAndHash(receipt: Omit<LegacyReceiptBase, 'metadata'>): {
    canonical: string;
    hash_sha256: string;
};
export type LegacySignOptions = {
    signer_id: string;
    kid?: string;
    canonical?: string;
    privateKeyPem: string;
};
export declare function signReceiptEd25519Sha256(receipt: Omit<LegacyReceiptBase, 'metadata'>, opts: LegacySignOptions): LayeredReceiptV1;
export type LegacyVerifyOptions = {
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
export declare function verifyReceiptEd25519Sha256(receipt: LayeredReceiptV1 | LegacyReceiptBase, opts: LegacyVerifyOptions): VerifyReceiptResult;
export declare function enforceCanonicalFromEns(layeredReceipt: LayeredReceiptV1, ensCanonical: string): {
    ok: boolean;
    reason?: string;
};
/** @deprecated Converts the legacy layered structure back into the 1.0.0 metadata envelope. */
export declare function toLegacyReceiptEnvelope(layeredReceipt: LayeredReceiptV1): LegacyReceiptBase;
//# sourceMappingURL=receipt-v1.d.ts.map