import type { ErrorObject, ValidateFunction } from 'ajv';

export const COMMAND_LAYER_CURRENT_LINE = '1.1.0' as const;
export const DEFAULT_SCHEMA_VERSION = 'v1' as const;
export const COMMONS_CONTRACT = 'commons' as const;
export const COMMERCIAL_CONTRACT = 'commercial' as const;
export const DEFAULT_CANONICAL_ID = 'json.sorted_keys.v1' as const;

export type CommandLayerLineVersion = typeof COMMAND_LAYER_CURRENT_LINE;
export type SchemaVersion = typeof DEFAULT_SCHEMA_VERSION | string;
export type ContractTier = typeof COMMONS_CONTRACT | typeof COMMERCIAL_CONTRACT;
export type ReceiptStatus = 'ok' | 'error';

export interface TraceContext {
  [key: string]: unknown;
}

export interface CommonsRequest {
  payload: unknown;
  trace?: TraceContext;
}

export interface CommercialTerms {
  [key: string]: unknown;
}

export interface CommercialRequest extends CommonsRequest {
  commercial: CommercialTerms;
}

export type NormalizedRequest = CommonsRequest;
export type NormalizedCommercialRequest = CommercialRequest;

export interface SchemaClientOptions {
  schemaHost: string;
  timeoutMs?: number;
  lineVersion?: CommandLayerLineVersion;
}

export interface ValidatorRequest {
  contract: ContractTier;
  verb: string;
  version?: SchemaVersion;
  lineVersion?: CommandLayerLineVersion;
}

export type AsyncValidator = ValidateFunction;

export interface CommonsReceipt {
  line: CommandLayerLineVersion;
  contract: typeof COMMONS_CONTRACT;
  verb: string;
  version: SchemaVersion;
  trace?: TraceContext;
  payload: unknown;
  status: ReceiptStatus;
  result?: unknown;
  error?: unknown;
}

export interface CommercialReceipt extends Omit<CommonsReceipt, 'contract'> {
  contract: typeof COMMERCIAL_CONTRACT;
  commercial: CommercialTerms;
}

export type CommandLayerReceipt = CommonsReceipt | CommercialReceipt;

export interface ReceiptRuntimeMetadata {
  [key: string]: unknown;
}

export interface Proof {
  alg: 'ed25519' | string;
  kid?: string;
  signer_id: string;
  canonical: string;
  signature: string;
}

export interface SignedReceiptLayer {
  proof: Proof;
}

export interface LayeredReceipt<TReceipt extends CommandLayerReceipt = CommandLayerReceipt> {
  receipt: TReceipt;
  runtime?: ReceiptRuntimeMetadata;
}

export interface SignedLayeredReceipt<TReceipt extends CommandLayerReceipt = CommandLayerReceipt> extends LayeredReceipt<TReceipt> {
  signature: SignedReceiptLayer;
}

/** @deprecated Legacy 1.0.0 envelope; use CommandLayerReceipt. */
export interface LegacySignedReceiptEnvelope {
  verb?: string;
  version?: string;
  x402?: unknown;
  trace?: unknown;
  payload?: unknown;
  status?: string;
  result?: unknown;
  metadata: Record<string, unknown> & {
    proof: Proof;
  };
}

export interface SignOptions {
  privateKey: Uint8Array | string;
  signer_id: string;
  kid?: string;
  canonical?: string;
}

export interface VerifyOptions {
  pubkey: Uint8Array | string;
  canonical?: string;
}

export interface AttachProofOptions {
  alg: string;
  kid?: string;
  signer_id: string;
  canonical: string;
  signature: string;
}

export interface EnsResolveOptions {
  ensName: string;
  provider?: unknown;
}

export interface EnsSignerInfo {
  pubkeyRaw32: Uint8Array;
  pubkeyEncoded: string;
  kid?: string;
  canonical?: string;
  signer_id: string;
  alg: 'ed25519';
}

export type CompactAjvError = Pick<ErrorObject, 'instancePath' | 'keyword' | 'message' | 'params'>;
