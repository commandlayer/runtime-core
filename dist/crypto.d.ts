/** sha256 hex digest of UTF-8 text */
export declare function sha256HexUtf8(text: string): string;
/**
 * Ed25519 signature over UTF-8 bytes of `message` (string).
 * Node's crypto.sign/verify for Ed25519 uses `null` as the algorithm.
 */
export declare function signEd25519MessageBase64(message: string, privateKeyPem: string): string;
export declare function verifyEd25519MessageBase64(message: string, signatureB64: string, publicKeyPemOrDer: string): boolean;
/** base64url helpers for compatibility */
export declare function base64UrlToBase64(b64url: string): string;
export declare function base64ToBase64Url(b64: string): string;
//# sourceMappingURL=crypto.d.ts.map