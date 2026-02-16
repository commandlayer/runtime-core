import { extractEd25519Raw32FromSpkiDer, fromBase64Url, parsePemToDer, toBase64Url } from './encoding.js';
const TXT_SIG_PUB = 'cl.sig.pub';
const TXT_SIG_KID = 'cl.sig.kid';
const TXT_SIG_CANONICAL = 'cl.sig.canonical';
const TXT_RECEIPT_PEM = 'cl.receipt.pubkey.pem';
function collapseTxt(value) {
    if (typeof value === 'string')
        return value;
    if (Array.isArray(value)) {
        const flattened = value.flat(Infinity).filter((v) => typeof v === 'string');
        return flattened.join('');
    }
    return undefined;
}
async function resolveTextRecord(provider, ensName, key) {
    if (!provider) {
        throw new Error('ENS provider is required');
    }
    if (typeof provider.getText === 'function') {
        const val = await provider.getText(ensName, key);
        return collapseTxt(val);
    }
    if (typeof provider.getResolver === 'function') {
        const resolver = await provider.getResolver(ensName);
        if (resolver && typeof resolver.getText === 'function') {
            const val = await resolver.getText(key);
            return collapseTxt(val);
        }
    }
    throw new Error('Unsupported ENS provider interface');
}
function parseSigPub(raw) {
    const [alg, encoded] = raw.split(':', 2);
    if (alg !== 'ed25519' || !encoded) {
        throw new Error('Invalid cl.sig.pub format; expected ed25519:<base64url_raw32>');
    }
    const decoded = fromBase64Url(encoded);
    if (decoded.length !== 32) {
        throw new Error('Invalid cl.sig.pub key length, expected 32 bytes');
    }
    return decoded;
}
export async function resolveSignerFromENS(options) {
    const sigPub = await resolveTextRecord(options.provider, options.ensName, TXT_SIG_PUB);
    const kid = await resolveTextRecord(options.provider, options.ensName, TXT_SIG_KID);
    const canonical = await resolveTextRecord(options.provider, options.ensName, TXT_SIG_CANONICAL);
    let raw32;
    if (sigPub) {
        raw32 = parseSigPub(sigPub);
    }
    else {
        const pem = await resolveTextRecord(options.provider, options.ensName, TXT_RECEIPT_PEM);
        if (!pem) {
            throw new Error('No signer key TXT records found on ENS name');
        }
        raw32 = extractEd25519Raw32FromSpkiDer(parsePemToDer(pem));
    }
    return {
        pubkeyRaw32: raw32,
        pubkeyEncoded: toBase64Url(raw32),
        kid: kid || undefined,
        canonical: canonical || undefined,
        signer_id: options.ensName,
        alg: 'ed25519'
    };
}
//# sourceMappingURL=ens.js.map