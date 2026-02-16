import type { ErrorObject } from 'ajv';
import type { CompactAjvError } from './types.js';
export declare class RuntimeCoreError extends Error {
    code: string;
    constructor(code: string, message: string);
}
export declare function formatAjvErrors(errors: ErrorObject[] | null | undefined): CompactAjvError[];
//# sourceMappingURL=errors.d.ts.map