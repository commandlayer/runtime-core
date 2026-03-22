import type { AttachProofOptions, CommandLayerReceipt, CommercialReceipt, CommonsReceipt, LayeredReceipt, LegacySignedReceiptEnvelope, ReceiptRuntimeMetadata, SignOptions, SignedLayeredReceipt, VerifyOptions } from './types.js';
export declare function buildCommonsReceipt(input: Omit<CommonsReceipt, 'line' | 'contract'> & Partial<Pick<CommonsReceipt, 'line' | 'contract'>>): CommonsReceipt;
export declare function buildCommercialReceipt(input: Omit<CommercialReceipt, 'line' | 'contract'> & Partial<Pick<CommercialReceipt, 'line' | 'contract'>>): CommercialReceipt;
export declare function buildReceipt(input: CommandLayerReceipt): CommandLayerReceipt;
export declare function createLayeredReceipt<TReceipt extends CommandLayerReceipt>(receipt: TReceipt, runtime?: ReceiptRuntimeMetadata): LayeredReceipt<TReceipt>;
export declare function canonicalizeReceipt(receipt: CommandLayerReceipt): string;
export declare function hashReceiptCanonical(canonical: string): Uint8Array;
export declare function attachProof<TReceipt extends CommandLayerReceipt>(receipt: TReceipt, options: AttachProofOptions): SignedLayeredReceipt<TReceipt>;
export declare function signReceiptEd25519<TReceipt extends CommandLayerReceipt>(receipt: TReceipt, options: SignOptions): SignedLayeredReceipt<TReceipt>;
export declare function verifyReceiptSignature(receipt: SignedLayeredReceipt, options: VerifyOptions): boolean;
/** @deprecated Legacy 1.0.0 metadata.proof envelope. */
export declare function toLegacySignedReceipt(receipt: SignedLayeredReceipt, runtimeMetadata?: Record<string, unknown>): LegacySignedReceiptEnvelope;
//# sourceMappingURL=receipt.d.ts.map