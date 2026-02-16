function swapWww(hostname) {
    if (hostname.startsWith('www.')) {
        return hostname.slice(4);
    }
    return `www.${hostname}`;
}
function buildUrl(base, kind, params) {
    const path = `/schemas/${params.tier}/${params.verb}/${params.version}/${kind}.schema.json`;
    return new URL(path, base).toString();
}
export function createSchemaClient(options) {
    const timeoutMs = options.timeoutMs ?? 5000;
    const baseUrl = new URL(options.schemaHost);
    const fetchCache = new Map();
    const validatorCache = new Map();
    let ajvPromise;
    async function getAjv() {
        if (!ajvPromise) {
            ajvPromise = (async () => {
                const ajvModule = await import('ajv');
                const Ajv = ajvModule.default;
                return new Ajv({
                    strict: true,
                    allErrors: true,
                    loadSchema: async (uri) => {
                        const schema = await fetchJson(uri);
                        return schema;
                    }
                });
            })();
        }
        return ajvPromise;
    }
    async function fetchWithTimeout(url) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
            return await fetch(url, { signal: controller.signal });
        }
        finally {
            clearTimeout(timer);
        }
    }
    async function fetchJson(url) {
        const cached = fetchCache.get(url);
        if (cached)
            return cached;
        const request = (async () => {
            const tryUrls = [url];
            const parsed = new URL(url);
            tryUrls.push(new URL(`${parsed.protocol}//${swapWww(parsed.hostname)}${parsed.pathname}${parsed.search}`).toString());
            let lastError;
            for (const candidate of tryUrls) {
                try {
                    const response = await fetchWithTimeout(candidate);
                    if (!response.ok) {
                        throw new Error(`Schema fetch failed (${response.status}) for ${candidate}`);
                    }
                    const contentType = response.headers.get('content-type') ?? '';
                    if (!contentType.toLowerCase().includes('application/json')) {
                        throw new Error(`Unexpected content-type for schema: ${contentType || 'unknown'}`);
                    }
                    return await response.json();
                }
                catch (error) {
                    lastError = error;
                }
            }
            throw lastError instanceof Error ? lastError : new Error('Schema fetch failed');
        })();
        fetchCache.set(url, request);
        return request;
    }
    async function getValidator(kind, params) {
        const key = `${kind}:${params.tier}:${params.verb}:${params.version}`;
        const existing = validatorCache.get(key);
        if (existing)
            return existing;
        const promise = (async () => {
            const schemaUrl = buildUrl(baseUrl, kind, params);
            const schema = await fetchJson(schemaUrl);
            const ajv = await getAjv();
            return ajv.compileAsync(schema);
        })();
        validatorCache.set(key, promise);
        return promise;
    }
    return {
        fetchJson,
        getRequestValidator: (params) => getValidator('request', params),
        getReceiptValidator: (params) => getValidator('receipt', params)
    };
}
//# sourceMappingURL=schema-client.js.map