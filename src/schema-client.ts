import type { ValidateFunction } from 'ajv';
import type { AsyncValidator, SchemaClientOptions, ValidatorRequest } from './types.js';

interface SchemaClient {
  fetchJson: (url: string) => Promise<unknown>;
  getRequestValidator: (params: ValidatorRequest) => Promise<AsyncValidator>;
  getReceiptValidator: (params: ValidatorRequest) => Promise<AsyncValidator>;
}

interface AjvLike {
  compileAsync(schema: object): Promise<ValidateFunction>;
}

function swapWww(hostname: string): string {
  if (hostname.startsWith('www.')) {
    return hostname.slice(4);
  }
  return `www.${hostname}`;
}

function buildUrl(base: URL, kind: 'request' | 'receipt', params: ValidatorRequest): string {
  const path = `/schemas/${params.tier}/${params.verb}/${params.version}/${kind}.schema.json`;
  return new URL(path, base).toString();
}

export function createSchemaClient(options: SchemaClientOptions): SchemaClient {
  const timeoutMs = options.timeoutMs ?? 5000;
  const baseUrl = new URL(options.schemaHost);
  const fetchCache = new Map<string, Promise<unknown>>();
  const validatorCache = new Map<string, Promise<AsyncValidator>>();
  let ajvPromise: Promise<AjvLike> | undefined;

  async function getAjv(): Promise<AjvLike> {
    if (!ajvPromise) {
      ajvPromise = (async () => {
        const ajvModule = await import('ajv');
        const Ajv = ajvModule.default;
        return new Ajv({
          strict: true,
          allErrors: true,
          loadSchema: async (uri: string) => {
            const schema = await fetchJson(uri);
            return schema as object;
          }
        }) as AjvLike;
      })();
    }
    return ajvPromise;
  }

  async function fetchWithTimeout(url: string): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetch(url, { signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  async function fetchJson(url: string): Promise<unknown> {
    const cached = fetchCache.get(url);
    if (cached) return cached;

    const request = (async () => {
      const tryUrls = [url];
      const parsed = new URL(url);
      tryUrls.push(new URL(`${parsed.protocol}//${swapWww(parsed.hostname)}${parsed.pathname}${parsed.search}`).toString());

      let lastError: unknown;
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
        } catch (error) {
          lastError = error;
        }
      }

      throw lastError instanceof Error ? lastError : new Error('Schema fetch failed');
    })();

    fetchCache.set(url, request);
    return request;
  }

  async function getValidator(kind: 'request' | 'receipt', params: ValidatorRequest): Promise<AsyncValidator> {
    const key = `${kind}:${params.tier}:${params.verb}:${params.version}`;
    const existing = validatorCache.get(key);
    if (existing) return existing;

    const promise = (async () => {
      const schemaUrl = buildUrl(baseUrl, kind, params);
      const schema = await fetchJson(schemaUrl);
      const ajv = await getAjv();
      return ajv.compileAsync(schema as object);
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
