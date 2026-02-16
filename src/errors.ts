import type { ErrorObject } from 'ajv';
import type { CompactAjvError } from './types.js';

export class RuntimeCoreError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'RuntimeCoreError';
    this.code = code;
  }
}

export function formatAjvErrors(errors: ErrorObject[] | null | undefined): CompactAjvError[] {
  if (!errors?.length) {
    return [];
  }

  return errors.map((error) => ({
    instancePath: error.instancePath,
    keyword: error.keyword,
    message: error.message,
    params: error.params
  }));
}
