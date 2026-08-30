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
 *   - Machine-Service Factory execution evidence (commandlayer.execution-evidence.v1)
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
  type ResolveSignerFromENSOptions,
} from "./ens.js";

// Machine-Service Factory execution evidence
export {
  FACTORY_EXECUTION_RECEIPT_PROFILE,
  assertFactoryExecutionReceipt,
  signFactoryExecutionReceipt,
  signFactoryExecutionReceiptWithSigner,
  verifyFactoryExecutionReceipt,
  type AcceptanceStatus,
  type FactoryProviderStep,
  type FactoryAcceptanceCheck,
  type FactoryExecutionEvidence,
  type FactoryExecutionReceipt,
  type FactoryExecutionProof,
  type SignedFactoryExecutionReceipt,
  type SignFactoryExecutionReceiptOptions,
  type FactoryExternalSignRequest,
  type FactoryExternalSignature,
  type FactoryExternalSigner,
  type SignFactoryExecutionReceiptWithSignerOptions,
  type FactoryVerificationKey,
  type ResolveFactoryVerificationKeyInput,
  type FactoryVerificationKeyResolver,
  type VerifyFactoryExecutionReceiptOptions,
  type VerifyFactoryExecutionReceiptResult,
} from "./execution-evidence.js";

// CommandLayer canonical proof envelope APIs
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
