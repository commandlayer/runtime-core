function normalizeTrace(trace) {
    if (trace && typeof trace === 'object' && !Array.isArray(trace)) {
        return { ...trace };
    }
    return undefined;
}
function normalizePayload(body) {
    if (Object.prototype.hasOwnProperty.call(body, 'payload')) {
        return body.payload;
    }
    return body.input;
}
export function normalizeCommonsRequest(body) {
    const safeBody = body ?? {};
    return {
        payload: normalizePayload(safeBody),
        ...(normalizeTrace(safeBody.trace) ? { trace: normalizeTrace(safeBody.trace) } : {})
    };
}
export function normalizeCommercialRequest(body) {
    const safeBody = body ?? {};
    const commercial = (safeBody.commercial ?? safeBody.payment);
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
export function normalizeRequest(body) {
    return normalizeCommonsRequest(body);
}
//# sourceMappingURL=normalize.js.map