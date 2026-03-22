import type { ValidateFunction } from 'ajv';
import type {
  AsyncValidator,
  CommandLayerLineVersion,
  ContractTier,
  SchemaClientOptions,
  SchemaVersion,
  ValidatorRequest
} from './types.js';
import { COMMAND_LAYER_CURRENT_LINE, DEFAULT_SCHEMA_VERSION } from './types.js';

interface SchemaClient {
  fetchJson: (url: string) => Promise<unknown>;
  getRequestValidator: (params: ValidatorRequest) => Promise<AsyncValidator>;
  getReceiptValidator: (params: ValidatorRequest) => Promise<AsyncValidator>;
  buildSchemaUrl: (kind: 'request' | 'receipt', params: ValidatorRequest) => string;
}

interface AjvLike {
  compileAsync(schema: object): Promise<ValidateFunction>;
}

function swapWww(hostname: string): string {
  return hostname.startsWith('www.') ? hostname.slice(4) : `www.${hostname}`;
}

export function buildSchemaPath(params: {
  contract: ContractTier;
  verb: string;
  version?: SchemaVersion;
  lineVersion?: CommandLayerLineVersion;
  kind: 'request' | 'receipt';
}): string {
  const schemaVersion = params.version ?? DEFAULT_SCHEMA_VERSION;
  const lineVersion = params.lineVersion ?? COMMAND_LAYER_CURRENT_LINE;
  return `/schemas/${lineVersion}/${params.contract}/${params.verb}/${schemaVersion}/${params.kind}.schema.json`;
}

/** @deprecated Legacy pre-1.1.0 schema path format. */
export function buildLegacySchemaPath(kind: 'request' | 'receipt', params: { tier: string; verb: string; version: string }): string {
  return `/schemas/${params.tier}/${params.verb}/${params.version}/${kind}.schema.json`;
}

export function createSchemaClient(options: SchemaClientOptions): SchemaClient {
  const timeoutMs = options.timeoutMs ?? 5000;
  const baseUrl = new URL(options.schemaHost);
  const defaultLineVersion = options.lineVersion ?? COMMAND_LAYER_CURRENT_LINE;
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
          loadSchema: async (uri: string) => (await fetchJson(uri)) as object
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
      const parsed = new URL(url);
      const tryUrls = [url, new URL(`${parsed.protocol}//${swapWww(parsed.hostname)}${parsed.pathname}${parsed.search}`).toString()];
      let lastError: unknown;

      for (const candidate of tryUrls) {
        try {
          const response = await fetchWithTimeout(candidate);
          if (!response.ok) throw new Error(`Schema fetch failed (${response.status}) for ${candidate}`);

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

  function buildSchemaUrl(kind: 'request' | 'receipt', params: ValidatorRequest): string {
    const path = buildSchemaPath({
      contract: params.contract,
      verb: params.verb,
      version: params.version,
      lineVersion: params.lineVersion ?? defaultLineVersion,
      kind
    });
    return new URL(path, baseUrl).toString();
  }

  async function getValidator(kind: 'request' | 'receipt', params: ValidatorRequest): Promise<AsyncValidator> {
    const contract = params.contract;
    const version = params.version ?? DEFAULT_SCHEMA_VERSION;
    const lineVersion = params.lineVersion ?? defaultLineVersion;
    const key = `${kind}:${lineVersion}:${contract}:${params.verb}:${version}`;
    const existing = validatorCache.get(key);
    if (existing) return existing;

    const promise = (async () => {
      const schema = await fetchJson(buildSchemaUrl(kind, params));
      const ajv = await getAjv();
      return ajv.compileAsync(schema as object);
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
