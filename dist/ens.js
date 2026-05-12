/**
 * @commandlayer/runtime-core — ens.ts
 *
 * ENS text record resolution for CommandLayer signer keys.
 *
 * ENS record format (production, locked):
 *   cl.sig.pub       = ed25519:<standard_base64_raw32>
 *   cl.sig.kid       = <short key identifier, e.g. vC4WbcNoq2znSCiQ>
 *   cl.sig.canonical = json.sorted_keys.v1
 *   cl.receipt.signer = <ens name>
 *
 * NO hardcoded fallback keys. ENS resolution failure is a hard error.
 * If you need test fixtures, use test/fixtures/ens-mock.ts.
 */
import { ENS_KEY_PUB, ENS_KEY_KID, ENS_KEY_CANONICAL, CANONICAL_METHOD, parsePublicKey, } from "./crypto.js";
// ── Resolution ────────────────────────────────────────────────────────────────
/**
 * Resolve a CommandLayer signer record from ENS.
 *
 * Throws on:
 * - No resolver found for the ENS name
 * - Missing cl.sig.pub record
 * - Malformed cl.sig.pub (not ed25519: prefix or wrong key length)
 * - cl.sig.canonical mismatch (if present and not json.sorted_keys.v1)
 *
 * Never falls back to hardcoded keys.
 */
export async function resolveSignerFromENS(ensName, provider) {
    let resolver;
    try {
        resolver = await provider.getResolver(ensName);
    }
    catch (err) {
        throw new Error(`ENS resolution failed for "${ensName}": ${err.message}`);
    }
    if (!resolver) {
        throw new Error(`No ENS resolver found for "${ensName}". ` +
            `Verify the name is registered and has a resolver set.`);
    }
    // Fetch all relevant text records in parallel
    let pubValue;
    let kidValue;
    let canonicalValue;
    try {
        [pubValue, kidValue, canonicalValue] = await Promise.all([
            resolver.getText(ENS_KEY_PUB),
            resolver.getText(ENS_KEY_KID),
            resolver.getText(ENS_KEY_CANONICAL),
        ]);
    }
    catch (err) {
        throw new Error(`Failed to fetch ENS text records for "${ensName}": ${err.message}`);
    }
    if (!pubValue) {
        throw new Error(`ENS name "${ensName}" has no ${ENS_KEY_PUB} text record. ` +
            `Set cl.sig.pub = ed25519:<standard_base64_raw32> on the ENS name.`);
    }
    // Validate canonical method if present
    if (canonicalValue && canonicalValue !== CANONICAL_METHOD) {
        throw new Error(`ENS name "${ensName}" specifies unsupported canonical method: ` +
            `"${canonicalValue}". Only "${CANONICAL_METHOD}" is supported.`);
    }
    // Parse the public key — throws on malformed input
    const rawPublicKey = parsePublicKey(pubValue);
    return {
        name: ensName,
        rawPublicKey,
        kid: kidValue ?? "",
        canonical: canonicalValue ?? CANONICAL_METHOD,
    };
}
/**
 * Resolve the public key only (convenience wrapper).
 * Use resolveSignerFromENS for full record access.
 */
export async function resolvePublicKeyFromENS(ensName, provider) {
    const record = await resolveSignerFromENS(ensName, provider);
    return record.rawPublicKey;
}
//# sourceMappingURL=ens.js.map