/**
 * @commandlayer/runtime-core — crypto.ts
 *
 * PROTOCOL SIGNING CONTRACT (canonical, locked to ENS production record):
 *   cl.sig.canonical = json.sorted_keys.v1
 *   cl.sig.pub       = ed25519:<standard_base64_raw32>   (= padding, +/ charset)
 *   signing message  = Ed25519.sign(raw_canonical_utf8_bytes)
 *                      where canonical = canonicalizeSortedKeysV1(payload)
 *
 * DO NOT change the signing message without a protocol version bump and
 * coordinated migration across all repos.
 */
export declare const PROTOCOL_VERSION: "1.1.0";
export declare const CANONICAL_METHOD: "json.sorted_keys.v1";
export declare const SIGNATURE_ALG: "ed25519";
/** The ENS text record key for the signer's public key. */
export declare const ENS_KEY_PUB: "cl.sig.pub";
export declare const ENS_KEY_KID: "cl.sig.kid";
export declare const ENS_KEY_CANONICAL: "cl.sig.canonical";
export declare const ENS_KEY_SIGNER: "cl.receipt.signer";
/**
 * Encode a raw 32-byte Ed25519 public key to the ENS cl.sig.pub format:
 *   ed25519:<standard_base64>
 *
 * Standard base64: uses A-Z a-z 0-9 +/ with = padding.
 * This matches the live ENS record for runtime.commandlayer.eth.
 */
export declare function encodePublicKey(rawBytes: Uint8Array): string;
/**
 * Parse an ENS cl.sig.pub value to raw 32-byte public key.
 * Accepts: ed25519:<standard_base64>
 * Rejects anything that isn't 32 bytes after decode.
 */
export declare function parsePublicKey(ensPubValue: string): Uint8Array;
/**
 * Sign a canonical string using an Ed25519 private key (PEM or DER).
 *
 * Signing message: raw UTF-8 bytes of the canonical string.
 * NOT sha256(canonical) — signs the data directly.
 *
 * Returns: standard base64-encoded 64-byte signature.
 */
export declare function signCanonical(canonicalString: string, privateKeyPem: string): string;
/**
 * Verify an Ed25519 signature over a canonical string.
 *
 * @param canonicalString  The canonical JSON string that was signed
 * @param signatureBase64  Standard base64-encoded signature (64 bytes)
 * @param publicKeyPem     PEM-encoded Ed25519 public key
 *
 * Returns true if signature is valid, false otherwise.
 * Never throws on invalid signature — only throws on malformed inputs.
 */
export declare function verifyCanonical(canonicalString: string, signatureBase64: string, publicKeyPem: string): boolean;
/**
 * Verify using a raw 32-byte public key (from ENS cl.sig.pub).
 * Converts to PEM internally then delegates to verifyCanonical.
 */
export declare function verifyCanonicalWithRawKey(canonicalString: string, signatureBase64: string, rawPublicKey: Uint8Array): boolean;
export interface Ed25519KeyPair {
    privateKeyPem: string;
    publicKeyPem: string;
    /** Raw 32-byte public key, ready for ENS cl.sig.pub encoding */
    rawPublicKey: Uint8Array;
    /** Formatted ENS cl.sig.pub value */
    ensPubValue: string;
}
export declare function generateEd25519KeyPair(): Ed25519KeyPair;
//# sourceMappingURL=crypto.d.ts.map