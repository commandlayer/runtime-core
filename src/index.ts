/**
 * @commandlayer/runtime-core
 *
 * The single protocol implementation artifact for the CommandLayer ecosystem.
 * All other repos import from here — nothing is reimplemented downstream.
 *
 * Public API surface:
 *   - Protocol constants
 *   - Canonicalization (json.sorted_keys.v1)
 *   - Canonical SHA-256 hashing
 *   - Ed25519 crypto (sign, verify, key encoding)
 *   - ENS resolution
 *   - Receipt building and verification (v1.1.0)
 *   - Rail-neutral Machine-Service Factory execution receipts
 *   - Strict CLAS scoped execution/settlement proof signing and verification
 *   - Legacy scoped-proof verification compatibility
 *   - Test vectors
 *   - Backward-compatibility shims (for runtime/server.mjs)
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

// Canonicalization and hashing
export { canonicalize, CANONICAL_TEST_VECTORS } from "./canonicalize.js";
export { sha256Text, hashCanonical } from "./hash.js";

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
  type ResolveSignerFromENSOptions,
} from "./ens.js";

// Rail-neutral Machine-Service Factory execution receipt APIs. These do not
// require ENS, ERC-8004, x402, or any other identity/settlement adapter.
export {
  FACTORY_EXECUTION_RECEIPT_PROFILE,
  FACTORY_EXECUTION_PROOF_COVERS,
  buildFactoryExecutionPayload,
  createFactoryExecutionProof,
  signFactoryExecutionReceipt,
  verifyFactoryExecutionReceipt,
  type FactoryExecutionProofSignature,
  type FactoryExecutionProof,
  type FactoryExecutionReceipt,
  type SignFactoryExecutionReceiptOptions,
  type VerifyFactoryExecutionReceiptOptions,
  type VerifyFactoryExecutionReceiptResult,
} from "./factory-receipts.js";

// Legacy/compat proof envelope APIs. `verifyScopedProofs` remains available for
// older hash-bearing scoped proofs; new CLAS execution receipts should use the
// strict `verifyClasScopedProofs` surface exported below.
export {
  buildCanonicalProof,
  signCommandLayerReceipt,
  verifyCommandLayerReceipt,
  buildCoveredPayload,
  verifyScopedProof,
  verifyScopedProofs,
  SCOPED_PROOF_COVERS,
  isSignedCommandLayerReceipt,
  isSingleSignature,
  isMultiSignature,
  getPrimarySignature,
  type CommandLayerReceipt,
  type CommandLayerProof,
  type CommandLayerProofSignature,
  type CommandLayerProofSignatureRole,
  type CommandLayerProofSignatureWithRole,
  type CommandLayerProofSignatureField,
  type EnsVerificationRecord,
  type CommandLayerScopedProof,
  type ScopedProofType,
  type VerifyScopedProofResult,
  type VerifyScopedProofsResult,
  type VerifyScopedProofsOptions,
} from "./compat.js";

// Canonical CLAS `clas.execution.receipt.v1` scoped-proof APIs.
export {
  buildClasScopedPayload,
  createScopedProof,
  appendScopedProof,
  signScopedProof,
  signExecutionScopedProof,
  signSettlementScopedProof,
  verifyClasScopedProof,
  verifyClasScopedProofs,
  type ClasScopedSignature,
  type ClasScopedProof,
  type ClasExecutionReceipt,
  type SignScopedProofOptions,
  type VerifyClasScopedProofResult,
  type VerifyClasScopedProofsResult,
  type VerifyClasScopedProofsOptions,
} from "./scoped-proofs.js";
