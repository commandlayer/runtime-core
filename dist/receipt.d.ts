import type { AttachProofOptions, SignOptions, SignedReceipt, UnsignedReceipt, VerifyOptions } from './types.js';
export declare function buildUnsignedReceipt(input: UnsignedReceipt): UnsignedReceipt;
export declare function canonicalizeReceipt(unsigned: UnsignedReceipt): string;
export declare function hashReceiptCanonical(canonical: string): Uint8Array;
export declare function attachProof(unsigned: UnsignedReceipt, options: AttachProofOptions): SignedReceipt;
export declare function signReceiptEd25519(unsigned: UnsignedReceipt, options: SignOptions): SignedReceipt;
export declare function verifyReceiptSignature(receipt: SignedReceipt, options: VerifyOptions): boolean;
//# sourceMappingURL=receipt.d.ts.map