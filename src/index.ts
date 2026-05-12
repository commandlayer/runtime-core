/**
 * @commandlayer/runtime-core
 *
 * The single protocol implementation artifact for the CommandLayer ecosystem.
 * All other repos import from here — nothing is reimplemented downstream.
 *
 * Public API surface:
 *   - Protocol constants
 *   - Canonicalization (json.sorted_keys.v1)
 *   - Ed25519 crypto (sign, verify, key encoding)
 *   - ENS resolution
 *   - Receipt building and verification (v1.1.0)
 *   - Test vectors
 */

// Protocol constants
export {
  PROTOCOL_VERSION,
  CANONICAL_METHOD,
  SIGNATURE_ALG,
  ENS_KEY_PUB,
  ENS_KEY_KID,
  ENS_KEY_CANONICAL,
  ENS_KEY_SIGNER,
} from "./crypto.js";

// Canonicalization
export { canonicalize, CANONICAL_TEST_VECTORS } from "./canonicalize.js";

// Crypto primitives
export {
  encodePublicKey,
  parsePublicKey,
  signCanonical,
  verifyCanonical,
  verifyCanonicalWithRawKey,
  generateEd25519KeyPair,
  type Ed25519KeyPair,
} from "./crypto.js";

// ENS resolution
export {
  resolveSignerFromENS,
  resolvePublicKeyFromENS,
  type EnsSignerRecord,
  type EnsProvider,
  type EnsResolver,
} from "./ens.js";

// Receipt v1.1.0
export {
  signReceipt,
  verifyReceipt,
  isSignedLayeredReceipt,
  type ReceiptPayload,
  type ReceiptProof,
  type SignedLayeredReceipt,
  type SignReceiptOptions,
  type VerifyReceiptResult,
  type VerifyReceiptOptions,
} from "./receipt.js";
