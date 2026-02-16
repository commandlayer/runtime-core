import type { AsyncValidator, SchemaClientOptions, ValidatorRequest } from './types.js';
interface SchemaClient {
    fetchJson: (url: string) => Promise<unknown>;
    getRequestValidator: (params: ValidatorRequest) => Promise<AsyncValidator>;
    getReceiptValidator: (params: ValidatorRequest) => Promise<AsyncValidator>;
}
export declare function createSchemaClient(options: SchemaClientOptions): SchemaClient;
export {};
//# sourceMappingURL=schema-client.d.ts.map