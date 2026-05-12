/**
 * @commandlayer/runtime-core — receipt.ts
 *
 * v1.1.0 signed layered receipt builder and verifier.
 *
 * Proof field names (canonical, matches clas schema):
 *   proof.alg        — signature algorithm ("ed25519")
 *   proof.kid        — key identifier (from ENS cl.sig.kid)
 *   proof.signer_id  — ENS name of signer (e.g. runtime.commandlayer.eth)
 *   proof.canonical  — canonicalization method ("json.sorted_keys.v1")
 *   proof.signature  — standard base64-encoded Ed25519 signature (64 bytes)
 */
import { CANONICAL_METHOD } from "./canonicalize.js";
import { SIGNATURE_ALG, PROTOCOL_VERSION } from "./crypto.js";
export interface ReceiptPayload {
    verb: string;
    version: string;
    agent: string;
    timestamp: string;
    [key: string]: unknown;
}
export interface ReceiptProof {
    /** Signature algorithm. Always "ed25519". */
    alg: typeof SIGNATURE_ALG;
    /** Key identifier from ENS cl.sig.kid */
    kid: string;
    /** ENS name of the signer */
    signer_id: string;
    /** Canonicalization method. Always "json.sorted_keys.v1". */
    canonical: typeof CANONICAL_METHOD;
    /** Standard base64-encoded Ed25519 signature over the canonical receipt string */
    signature: string;
}
export interface SignedLayeredReceipt {
    receipt: ReceiptPayload;
    signature: {
        proof: ReceiptProof;
    };
}
export interface SignReceiptOptions {
    privateKeyPem: string;
    kid: string;
    signerEns: string;
}
/**
 * Build and sign a v1.1.0 layered receipt.
 *
 * Signing message: raw UTF-8 bytes of canonicalize(receipt)
 * Output signature: standard base64 (64 bytes)
 */
export declare function signReceipt(payload: ReceiptPayload, opts: SignReceiptOptions): SignedLayeredReceipt;
export interface VerifyReceiptResult {
    valid: boolean;
    checks: {
        structureValid: boolean;
        algValid: boolean;
        kidMatched: boolean;
        signerMatched: boolean;
        signatureValid: boolean;
    };
    reason?: string;
}
export interface VerifyReceiptOptions {
    /** Expected signer ENS name. If provided, signer_id must match. */
    expectedSigner?: string;
    /** Raw 32-byte public key. If provided, used for verification directly. */
    rawPublicKey?: Uint8Array;
    /** PEM public key. If provided, used for verification directly. */
    publicKeyPem?: string;
    /** Expected kid. If provided, proof.kid must match. */
    expectedKid?: string;
}
/**
 * Verify a v1.1.0 signed layered receipt.
 *
 * Returns a detailed result with per-check breakdown.
 * Never throws on invalid signature — only throws on missing required options.
 */
export declare function verifyReceipt(receipt: SignedLayeredReceipt, opts: VerifyReceiptOptions): VerifyReceiptResult;
/**
 * Type guard: check if an unknown value is a SignedLayeredReceipt.
 */
export declare function isSignedLayeredReceipt(value: unknown): value is SignedLayeredReceipt;
export { PROTOCOL_VERSION };
//# sourceMappingURL=receipt.d.ts.map