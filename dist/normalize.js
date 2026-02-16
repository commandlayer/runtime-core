export function normalizeRequest(body) {
    const safeBody = body ?? {};
    const payload = safeBody.payload ?? safeBody.input;
    return {
        x402: safeBody.x402,
        trace: safeBody.trace,
        payload
    };
}
//# sourceMappingURL=normalize.js.map