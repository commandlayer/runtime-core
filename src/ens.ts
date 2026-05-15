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

import {
  ENS_KEY_PUB,
  ENS_KEY_KID,
  ENS_KEY_CANONICAL,
  CANONICAL_METHOD,
  parsePublicKey,
} from "./crypto.js";

// Re-export so callers can reference the constant without importing crypto directly
export { ENS_KEY_SIGNER } from "./crypto.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface EnsEndpointMetadata {
  runtime?: string;
  verify?: string;
  mcp?: string;
  docs?: string;
  registry?: string;
}

export interface EnsSignerRecord {
  /** ENS name, e.g. runtime.commandlayer.eth */
  name: string;
  /** Raw 32-byte Ed25519 public key */
  rawPublicKey: Uint8Array;
  /** Short key identifier from cl.sig.kid */
  kid: string;
  /** Canonicalization method from cl.sig.canonical */
  canonical: string;
  /** Receipt signer identity from cl.receipt.signer */
  signer: string;
  /** Optional endpoint discovery metadata */
  endpoints: EnsEndpointMetadata;
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
 * Options object form of resolveSignerFromENS.
 * Use this when calling from code that prefers named parameters.
 */
export interface ResolveSignerFromENSOptions {
  ensName: string;
  provider: EnsProvider;
}

// ── Resolution ────────────────────────────────────────────────────────────────

/**
 * Resolve a CommandLayer signer record from ENS.
 *
 * Accepts either positional arguments or a single options object:
 *
 *   // Positional (preferred in library code):
 *   await resolveSignerFromENS('signer.commandlayer.eth', provider);
 *
 *   // Options object (preferred in application code):
 *   await resolveSignerFromENS({ ensName: 'signer.commandlayer.eth', provider });
 *
 * Throws on:
 * - No resolver found for the ENS name
 * - Missing cl.sig.pub record
 * - Malformed cl.sig.pub (not ed25519: prefix or wrong key length)
 * - cl.sig.canonical mismatch (if present and not json.sorted_keys.v1)
 *
 * Never falls back to hardcoded keys.
 */
export async function resolveSignerFromENS(
  ensNameOrOpts: string | ResolveSignerFromENSOptions,
  providerArg?: EnsProvider
): Promise<EnsSignerRecord> {
  let ensName: string;
  let provider: EnsProvider;

  if (typeof ensNameOrOpts === "string") {
    if (!providerArg) {
      throw new Error(
        "resolveSignerFromENS: provider is required as the second argument "
          + "when ensName is passed as a string."
      );
    }
    ensName = ensNameOrOpts;
    provider = providerArg;
  } else {
    ensName = ensNameOrOpts.ensName;
    provider = ensNameOrOpts.provider;
    if (!provider) {
      throw new Error("resolveSignerFromENS: provider is required in options object.");
    }
  }

  if (!ensName || typeof ensName !== "string") {
    throw new Error("resolveSignerFromENS: ensName must be a non-empty string.");
  }

  let resolver: EnsResolver | null;
  try {
    resolver = await provider.getResolver(ensName);
  } catch (err) {
    throw new Error(
      `ENS resolution failed for "${ensName}": ${(err as Error).message}`
    );
  }

  if (!resolver) {
    throw new Error(
      `No ENS resolver found for "${ensName}". `
        + `Verify the name is registered and has a resolver set.`
    );
  }

  // Fetch all relevant text records in parallel
  let pubValue: string | null;
  let kidValue: string | null;
  let canonicalValue: string | null;
  let signerValue: string | null;
  let endpointRuntime: string | null;
  let endpointVerify: string | null;
  let endpointMcp: string | null;
  let endpointDocs: string | null;
  let endpointRegistry: string | null;

  try {
    [pubValue, kidValue, canonicalValue, signerValue, endpointRuntime, endpointVerify, endpointMcp, endpointDocs, endpointRegistry] = await Promise.all([
      resolver.getText(ENS_KEY_PUB),
      resolver.getText(ENS_KEY_KID),
      resolver.getText(ENS_KEY_CANONICAL),
      resolver.getText("cl.receipt.signer"),
      resolver.getText("cl.endpoint.runtime"),
      resolver.getText("cl.endpoint.verify"),
      resolver.getText("cl.endpoint.mcp"),
      resolver.getText("cl.endpoint.docs"),
      resolver.getText("cl.endpoint.registry"),
    ]);
  } catch (err) {
    throw new Error(
      `Failed to fetch ENS text records for "${ensName}": ${
        (err as Error).message
      }`
    );
  }

  if (!pubValue) {
    throw new Error(
      `ENS name "${ensName}" has no ${ENS_KEY_PUB} text record. `
        + `Set cl.sig.pub = ed25519:<standard_base64_raw32> on the ENS name.`
    );
  }

  // Validate canonical method if present
  if (canonicalValue && canonicalValue !== CANONICAL_METHOD) {
    throw new Error(
      `ENS name "${ensName}" specifies unsupported canonical method: `
        + `"${canonicalValue}". Only "${CANONICAL_METHOD}" is supported.`
    );
  }

  // Parse the public key — throws on malformed input
  const rawPublicKey = parsePublicKey(pubValue);

  return {
    name: ensName,
    rawPublicKey,
    kid: kidValue ?? "",
    canonical: canonicalValue ?? CANONICAL_METHOD,
    signer: signerValue ?? ensName,
    endpoints: {
      ...(endpointRuntime ? { runtime: endpointRuntime } : {}),
      ...(endpointVerify ? { verify: endpointVerify } : {}),
      ...(endpointMcp ? { mcp: endpointMcp } : {}),
      ...(endpointDocs ? { docs: endpointDocs } : {}),
      ...(endpointRegistry ? { registry: endpointRegistry } : {}),
    },
  };
}

/**
 * Resolve the public key only (convenience wrapper).
 * Use resolveSignerFromENS for full record access.
 */
export async function resolvePublicKeyFromENS(
  ensNameOrOpts: string | ResolveSignerFromENSOptions,
  providerArg?: EnsProvider
): Promise<Uint8Array> {
  const record = await resolveSignerFromENS(ensNameOrOpts as string, providerArg);
  return record.rawPublicKey;
}
