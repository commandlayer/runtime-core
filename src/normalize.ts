import type { NormalizedRequest } from './types.js';

export function normalizeRequest(body: Record<string, unknown> | null | undefined): NormalizedRequest {
  const safeBody = body ?? {};
  const payload = safeBody.payload ?? safeBody.input;
  return {
    x402: safeBody.x402,
    trace: safeBody.trace,
    payload
  };
}
