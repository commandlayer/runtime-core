import type { CommercialRequest, CommonsRequest } from './types.js';
export declare function normalizeCommonsRequest(body: Record<string, unknown> | null | undefined): CommonsRequest;
export declare function normalizeCommercialRequest(body: Record<string, unknown> | null | undefined): CommercialRequest;
/**
 * Current-line default normalization targets Commons and intentionally ignores legacy x402 metadata.
 * @deprecated Prefer normalizeCommonsRequest or normalizeCommercialRequest.
 */
export declare function normalizeRequest(body: Record<string, unknown> | null | undefined): CommonsRequest;
//# sourceMappingURL=normalize.d.ts.map