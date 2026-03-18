import type { AttachProofOptions, CommonsReceipt, LayeredReceipt, ReceiptRuntimeMetadata, SignOptions, SignedLayeredReceipt, SignedReceipt, VerifyOptions } from './types.js';
export declare function buildReceipt(input: CommonsReceipt): CommonsReceipt;
/** @deprecated Use buildReceipt to create the canonical commons receipt. */
export declare const buildUnsignedReceipt: typeof buildReceipt;
export declare function createLayeredReceipt(receipt: CommonsReceipt, runtime?: ReceiptRuntimeMetadata): LayeredReceipt;
export declare function canonicalizeReceipt(receipt: CommonsReceipt): string;
export declare function hashReceiptCanonical(canonical: string): Uint8Array;
export declare function attachProof(receipt: CommonsReceipt, options: AttachProofOptions): SignedLayeredReceipt;
export declare function signReceiptEd25519(receipt: CommonsReceipt, options: SignOptions): SignedLayeredReceipt;
export declare function verifyReceiptSignature(receipt: SignedLayeredReceipt, options: VerifyOptions): boolean;
/**
 * @deprecated Converts a layered signed receipt into the legacy metadata.proof envelope.
 */
export declare function toLegacySignedReceipt(receipt: SignedLayeredReceipt, runtimeMetadata?: Record<string, unknown>): SignedReceipt;
//# sourceMappingURL=receipt.d.ts.map