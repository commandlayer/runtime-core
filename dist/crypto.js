import crypto from "crypto";
/** sha256 hex digest of UTF-8 text */
export function sha256HexUtf8(text) {
    return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}
/**
 * Ed25519 signature over UTF-8 bytes of `message` (string).
 * Node's crypto.sign/verify for Ed25519 uses `null` as the algorithm.
 */
export function signEd25519MessageBase64(message, privateKeyPem) {
    const sig = crypto.sign(null, Buffer.from(message, "utf8"), privateKeyPem);
    return Buffer.from(sig).toString("base64");
}
export function verifyEd25519MessageBase64(message, signatureB64, publicKeyPemOrDer) {
    const sig = Buffer.from(signatureB64, "base64");
    return crypto.verify(null, Buffer.from(message, "utf8"), publicKeyPemOrDer, sig);
}
/** base64url helpers for compatibility */
export function base64UrlToBase64(b64url) {
    let s = b64url.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4 !== 0)
        s += "=";
    return s;
}
export function base64ToBase64Url(b64) {
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
//# sourceMappingURL=crypto.js.map