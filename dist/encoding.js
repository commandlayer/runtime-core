export function toBase64Url(input) {
    return Buffer.from(input)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
}
export function fromBase64Url(input) {
    const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
    return new Uint8Array(Buffer.from(normalized + padding, 'base64'));
}
export function parsePemToDer(pem) {
    const body = pem
        .replace(/-----BEGIN PUBLIC KEY-----/g, '')
        .replace(/-----END PUBLIC KEY-----/g, '')
        .replace(/\s+/g, '');
    return new Uint8Array(Buffer.from(body, 'base64'));
}
export function extractEd25519Raw32FromSpkiDer(der) {
    if (der.length < 32) {
        throw new Error('Invalid SPKI DER length');
    }
    // Ed25519 SPKI often ends with BIT STRING containing 0x00 + 32-byte key.
    // We validate by reading the last 33 bytes and confirming leading 0x00.
    const tail = der.slice(-33);
    if (tail[0] !== 0x00) {
        throw new Error('Invalid Ed25519 SPKI: missing zero bit padding octet');
    }
    const key = tail.slice(1);
    if (key.length !== 32) {
        throw new Error('Invalid Ed25519 key length in SPKI');
    }
    return key;
}
//# sourceMappingURL=encoding.js.map