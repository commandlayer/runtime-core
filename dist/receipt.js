/**
 * @commandlayer/runtime-core — receipt.ts
 *
 * v1.1.0 signed layered receipt builder and verifier.
 *
 * Proof field names (canonical, matches clas schema):
 *   proof.alg        — signature algorithm ("ed25519")
 *   proof.kid        — key identifier (from ENS cl.sig.kid)
 *   proof.signer_id  — ENS name of signer (e.g. runtime.commandlayer.eth)
 *   proof.canonical  — canonicalization method ("json.sorted_keys.v1")
 *   proof.signature  — standard base64-encoded Ed25519 signature (64 bytes)
 */
import { canonicalize, CANONICAL_METHOD } from "./canonicalize.js";
import { signCanonical, verifyCanonical, verifyCanonicalWithRawKey, SIGNATURE_ALG, PROTOCOL_VERSION, } from "./crypto.js";
/**
 * Build and sign a v1.1.0 layered receipt.
 *
 * Signing message: raw UTF-8 bytes of canonicalize(receipt)
 * Output signature: standard base64 (64 bytes)
 */
export function signReceipt(payload, opts) {
    // Validate required fields
    if (!payload.verb)
        throw new Error("receipt.verb is required");
    if (!payload.agent)
        throw new Error("receipt.agent is required");
    if (!payload.timestamp)
        throw new Error("receipt.timestamp is required");
    const canonical = canonicalize(payload);
    const signature = signCanonical(canonical, opts.privateKeyPem);
    return {
        receipt: payload,
        signature: {
            proof: {
                alg: SIGNATURE_ALG,
                kid: opts.kid,
                signer_id: opts.signerEns,
                canonical: CANONICAL_METHOD,
                signature,
            },
        },
    };
}
/**
 * Verify a v1.1.0 signed layered receipt.
 *
 * Returns a detailed result with per-check breakdown.
 * Never throws on invalid signature — only throws on missing required options.
 */
export function verifyReceipt(receipt, opts) {
    if (!opts.rawPublicKey && !opts.publicKeyPem) {
        throw new Error("verifyReceipt requires either rawPublicKey or publicKeyPem");
    }
    const checks = {
        structureValid: false,
        algValid: false,
        kidMatched: false,
        signerMatched: false,
        signatureValid: false,
    };
    // Structure check
    if (!receipt?.receipt ||
        !receipt?.signature?.proof?.signature ||
        !receipt?.signature?.proof?.alg ||
        !receipt?.signature?.proof?.signer_id) {
        return {
            valid: false,
            checks,
            reason: "Receipt is missing required structure fields",
        };
    }
    checks.structureValid = true;
    const proof = receipt.signature.proof;
    // Algorithm check
    if (proof.alg !== SIGNATURE_ALG) {
        return {
            valid: false,
            checks,
            reason: `Unsupported algorithm "${proof.alg}". Only "${SIGNATURE_ALG}" is supported.`,
        };
    }
    checks.algValid = true;
    // Kid check (if expected)
    checks.kidMatched = opts.expectedKid
        ? proof.kid === opts.expectedKid
        : true;
    // Signer check (if expected)
    checks.signerMatched = opts.expectedSigner
        ? proof.signer_id === opts.expectedSigner
        : true;
    // Signature verification
    let canonical;
    try {
        canonical = canonicalize(receipt.receipt);
    }
    catch (err) {
        return {
            valid: false,
            checks,
            reason: `Canonicalization failed: ${err.message}`,
        };
    }
    try {
        if (opts.rawPublicKey) {
            checks.signatureValid = verifyCanonicalWithRawKey(canonical, proof.signature, opts.rawPublicKey);
        }
        else {
            checks.signatureValid = verifyCanonical(canonical, proof.signature, opts.publicKeyPem);
        }
    }
    catch (err) {
        return {
            valid: false,
            checks,
            reason: `Signature verification error: ${err.message}`,
        };
    }
    // ALL checks must pass for valid: true
    const valid = checks.structureValid &&
        checks.algValid &&
        checks.kidMatched &&
        checks.signerMatched &&
        checks.signatureValid;
    return {
        valid,
        checks,
        reason: valid
            ? undefined
            : Object.entries(checks)
                .filter(([, v]) => !v)
                .map(([k]) => `${k} failed`)
                .join(", "),
    };
}
/**
 * Type guard: check if an unknown value is a SignedLayeredReceipt.
 */
export function isSignedLayeredReceipt(value) {
    if (typeof value !== "object" || value === null)
        return false;
    const v = value;
    if (typeof v.receipt !== "object" || v.receipt === null)
        return false;
    if (typeof v.signature !== "object" || v.signature === null)
        return false;
    const sig = v.signature;
    if (typeof sig.proof !== "object" || sig.proof === null)
        return false;
    const proof = sig.proof;
    return (typeof proof.alg === "string" &&
        typeof proof.signature === "string" &&
        typeof proof.signer_id === "string");
}
export { PROTOCOL_VERSION };
//# sourceMappingURL=receipt.js.map