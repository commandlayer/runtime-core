import { COMMAND_LAYER_CURRENT_LINE, DEFAULT_SCHEMA_VERSION } from './types.js';
function swapWww(hostname) {
    return hostname.startsWith('www.') ? hostname.slice(4) : `www.${hostname}`;
}
export function buildSchemaPath(params) {
    const schemaVersion = params.version ?? DEFAULT_SCHEMA_VERSION;
    const lineVersion = params.lineVersion ?? COMMAND_LAYER_CURRENT_LINE;
    return `/schemas/${lineVersion}/${params.contract}/${params.verb}/${schemaVersion}/${params.kind}.schema.json`;
}
/** @deprecated Legacy pre-1.1.0 schema path format. */
export function buildLegacySchemaPath(kind, params) {
    return `/schemas/${params.tier}/${params.verb}/${params.version}/${kind}.schema.json`;
}
export function createSchemaClient(options) {
    const timeoutMs = options.timeoutMs ?? 5000;
    const baseUrl = new URL(options.schemaHost);
    const defaultLineVersion = options.lineVersion ?? COMMAND_LAYER_CURRENT_LINE;
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
                    loadSchema: async (uri) => (await fetchJson(uri))
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
            const parsed = new URL(url);
            const tryUrls = [url, new URL(`${parsed.protocol}//${swapWww(parsed.hostname)}${parsed.pathname}${parsed.search}`).toString()];
            let lastError;
            for (const candidate of tryUrls) {
                try {
                    const response = await fetchWithTimeout(candidate);
                    if (!response.ok)
                        throw new Error(`Schema fetch failed (${response.status}) for ${candidate}`);
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
    function buildSchemaUrl(kind, params) {
        const path = buildSchemaPath({
            contract: params.contract,
            verb: params.verb,
            version: params.version,
            lineVersion: params.lineVersion ?? defaultLineVersion,
            kind
        });
        return new URL(path, baseUrl).toString();
    }
    async function getValidator(kind, params) {
        const contract = params.contract;
        const version = params.version ?? DEFAULT_SCHEMA_VERSION;
        const lineVersion = params.lineVersion ?? defaultLineVersion;
        const key = `${kind}:${lineVersion}:${contract}:${params.verb}:${version}`;
        const existing = validatorCache.get(key);
        if (existing)
            return existing;
        const promise = (async () => {
            const schema = await fetchJson(buildSchemaUrl(kind, params));
            const ajv = await getAjv();
            return ajv.compileAsync(schema);
        })();
        validatorCache.set(key, promise);
        return promise;
    }
    return {
        fetchJson,
        buildSchemaUrl,
        getRequestValidator: (params) => getValidator('request', params),
        getReceiptValidator: (params) => getValidator('receipt', params)
    };
}
//# sourceMappingURL=schema-client.js.map