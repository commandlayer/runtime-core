declare module 'ajv' {
  export interface ErrorObject {
    instancePath: string;
    keyword: string;
    message?: string;
    params: Record<string, unknown>;
  }

  export interface ValidateFunction {
    (data: unknown): boolean;
    errors?: ErrorObject[] | null;
  }

  export default class Ajv {
    constructor(options?: Record<string, unknown>);
    compileAsync(schema: object): Promise<ValidateFunction>;
  }
}

declare module 'node:crypto' {
  export type KeyLike = unknown;
  export function createHash(algorithm: string): {
    update(data: string | Uint8Array, inputEncoding?: string): any;
    digest(): Uint8Array;
  };
  export function createPrivateKey(key: any): any;
  export function createPublicKey(key: any): any;
  export function sign(algorithm: any, data: Uint8Array, key: any): Uint8Array;
  export function verify(algorithm: any, data: Uint8Array, key: any, signature: Uint8Array): boolean;
  export function generateKeyPairSync(type: 'ed25519'): { privateKey: any; publicKey: any };
}

declare module 'node:test' {
  const test: (name: string, fn: () => void | Promise<void>) => void;
  export default test;
}

declare module 'node:assert/strict' {
  const assert: {
    deepEqual(actual: unknown, expected: unknown): void;
    equal(actual: unknown, expected: unknown): void;
  };
  export default assert;
}

declare const Buffer: any;
