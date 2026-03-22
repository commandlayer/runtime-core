import type {
  CommercialRequest,
  CommercialTerms,
  CommonsRequest,
  TraceContext
} from './types.js';

function normalizeTrace(trace: unknown): TraceContext | undefined {
  if (trace && typeof trace === 'object' && !Array.isArray(trace)) {
    return { ...(trace as TraceContext) };
  }
  return undefined;
}

function normalizePayload(body: Record<string, unknown>): unknown {
  if (Object.prototype.hasOwnProperty.call(body, 'payload')) {
    return body.payload;
  }
  return body.input;
}

export function normalizeCommonsRequest(body: Record<string, unknown> | null | undefined): CommonsRequest {
  const safeBody = body ?? {};
  return {
    payload: normalizePayload(safeBody),
    ...(normalizeTrace(safeBody.trace) ? { trace: normalizeTrace(safeBody.trace) } : {})
  };
}

export function normalizeCommercialRequest(body: Record<string, unknown> | null | undefined): CommercialRequest {
  const safeBody = body ?? {};
  const commercial = (safeBody.commercial ?? safeBody.payment) as CommercialTerms | undefined;
  if (!commercial || typeof commercial !== 'object' || Array.isArray(commercial)) {
    throw new Error('Commercial requests require a commercial metadata object');
  }

  return {
    ...normalizeCommonsRequest(safeBody),
    commercial: { ...commercial }
  };
}

/**
 * Current-line default normalization targets Commons and intentionally ignores legacy x402 metadata.
 * @deprecated Prefer normalizeCommonsRequest or normalizeCommercialRequest.
 */
export function normalizeRequest(body: Record<string, unknown> | null | undefined): CommonsRequest {
  return normalizeCommonsRequest(body);
}
