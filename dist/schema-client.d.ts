import type { AsyncValidator, CommandLayerLineVersion, ContractTier, SchemaClientOptions, SchemaVersion, ValidatorRequest } from './types.js';
interface SchemaClient {
    fetchJson: (url: string) => Promise<unknown>;
    getRequestValidator: (params: ValidatorRequest) => Promise<AsyncValidator>;
    getReceiptValidator: (params: ValidatorRequest) => Promise<AsyncValidator>;
    buildSchemaUrl: (kind: 'request' | 'receipt', params: ValidatorRequest) => string;
}
export declare function buildSchemaPath(params: {
    contract: ContractTier;
    verb: string;
    version?: SchemaVersion;
    lineVersion?: CommandLayerLineVersion;
    kind: 'request' | 'receipt';
}): string;
/** @deprecated Legacy pre-1.1.0 schema path format. */
export declare function buildLegacySchemaPath(kind: 'request' | 'receipt', params: {
    tier: string;
    verb: string;
    version: string;
}): string;
export declare function createSchemaClient(options: SchemaClientOptions): SchemaClient;
export {};
//# sourceMappingURL=schema-client.d.ts.map