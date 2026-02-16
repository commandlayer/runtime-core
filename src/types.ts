import type { ErrorObject, ValidateFunction } from 'ajv';

export interface NormalizedRequest {
  x402: unknown;
  trace: unknown;
  payload: unknown;
}

export interface SchemaClientOptions {
  schemaHost: string;
  timeoutMs?: number;
}

export interface ValidatorRequest {
  tier: string;
  verb: string;
  version: string;
}

export type AsyncValidator = ValidateFunction;

export interface UnsignedReceipt {
  verb: string;
  version: string;
  x402: unknown;
  trace: unknown;
  payload: unknown;
  status: string;
  result: unknown;
  metadata?: Record<string, unknown>;
}

export interface Proof {
  alg: 'ed25519' | string;
  kid?: string;
  signer_id: string;
  canonical: string;
  signature: string;
}

export interface SignedReceipt extends UnsignedReceipt {
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
