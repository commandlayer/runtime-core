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
export interface EnsSignerRecord {
    /** ENS name, e.g. runtime.commandlayer.eth */
    name: string;
    /** Raw 32-byte Ed25519 public key */
    rawPublicKey: Uint8Array;
    /** Short key identifier from cl.sig.kid */
    kid: string;
    /** Canonicalization method from cl.sig.canonical */
    canonical: string;
}
/**
 * Minimal ENS provider interface.
 * Compatible with ethers v6 EnsResolver and any custom resolver.
 */
export interface EnsProvider {
    getResolver(name: string): Promise<EnsResolver | null>;
}
export interface EnsResolver {
    getText(key: string): Promise<string | null>;
}
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
export declare function resolveSignerFromENS(ensName: string, provider: EnsProvider): Promise<EnsSignerRecord>;
/**
 * Resolve the public key only (convenience wrapper).
 * Use resolveSignerFromENS for full record access.
 */
export declare function resolvePublicKeyFromENS(ensName: string, provider: EnsProvider): Promise<Uint8Array>;
//# sourceMappingURL=ens.d.ts.map