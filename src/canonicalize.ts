/**
 * @commandlayer/runtime-core — canonicalize.ts
 *
 * Canonical JSON serialization for CommandLayer receipt signing.
 *
 * Method ID: json.sorted_keys.v1  (matches ENS cl.sig.canonical production record)
 *
 * Rules:
 *   - Keys sorted lexicographically at every level (recursive)
 *   - No undefined values (skipped, same as JSON.stringify default)
 *   - No Date objects (must be pre-serialized to ISO string by caller)
 *   - No circular references (throws)
 *   - Numbers: standard JSON (no Infinity, no NaN — both throw)
 *   - Arrays: order preserved (not sorted)
 *   - Unicode: standard JSON escaping (no additional escaping)
 *
 * This is the single canonical implementation for the CommandLayer protocol.
 * All other repos import from here — do not copy or reimplement.
 */

import { CANONICAL_METHOD } from "./crypto.js";

export { CANONICAL_METHOD };

/**
 * Canonicalize a value using json.sorted_keys.v1.
 *
 * Returns a stable JSON string suitable for Ed25519 signing.
 * The returned string is UTF-8 safe and deterministic across all
 * compliant implementations.
 *
 * @throws if value contains Date objects, Infinity, NaN, or circular refs
 */
export function canonicalize(value: unknown): string {
  return canonicalizeValue(value, new Set());
}

function canonicalizeValue(value: unknown, seen: Set<object>): string {
  if (value === null) return "null";
  if (value === undefined) return ""; // caller should filter undefined

  const type = typeof value;

  if (type === "boolean") return value ? "true" : "false";

  if (type === "number") {
    if (!isFinite(value as number)) {
      throw new Error(
        `canonicalize: non-finite number (${value}) is not valid JSON. ` +
          `Convert Infinity/NaN to null or a string before canonicalizing.`
      );
    }
    return JSON.stringify(value);
  }

  if (type === "string") return JSON.stringify(value);

  if (type === "bigint") {
    throw new Error(
      `canonicalize: BigInt (${value}n) is not valid JSON. ` +
        `Convert to string or number before canonicalizing.`
    );
  }

  if (value instanceof Date) {
    throw new Error(
      `canonicalize: Date objects must be pre-serialized to ISO strings. ` +
        `Use value.toISOString() before canonicalizing.`
    );
  }

  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error("canonicalize: circular reference");
    seen.add(value);
    const items = value.map((item) =>
      item === undefined ? "null" : canonicalizeValue(item, seen)
    );
    seen.delete(value);
    return `[${items.join(",")}]`;
  }

  if (type === "object") {
    if (seen.has(value as object))
      throw new Error("canonicalize: circular reference");
    seen.add(value as object);

    const obj = value as Record<string, unknown>;
    const sortedKeys = Object.keys(obj).sort();
    const pairs: string[] = [];

    for (const key of sortedKeys) {
      const v = obj[key];
      if (v === undefined) continue; // skip undefined values
      pairs.push(`${JSON.stringify(key)}:${canonicalizeValue(v, seen)}`);
    }

    seen.delete(value as object);
    return `{${pairs.join(",")}}`;
  }

  // functions, symbols — not serializable
  throw new Error(`canonicalize: unsupported type "${type}"`);
}

/**
 * Canonical test vectors for cross-repo validation.
 *
 * Every repo that imports @commandlayer/runtime-core should run these
 * in their test suite to confirm canonicalization behaves identically.
 *
 * Import: import { CANONICAL_TEST_VECTORS } from '@commandlayer/runtime-core/canonicalize'
 */
export const CANONICAL_TEST_VECTORS = [
  {
    description: "empty object",
    input: {},
    expected: "{}",
  },
  {
    description: "single key",
    input: { a: 1 },
    expected: '{"a":1}',
  },
  {
    description: "keys sorted lexicographically",
    input: { z: 1, a: 2, m: 3 },
    expected: '{"a":2,"m":3,"z":1}',
  },
  {
    description: "nested object keys sorted",
    input: { b: { z: 1, a: 2 }, a: 1 },
    expected: '{"a":1,"b":{"a":2,"z":1}}',
  },
  {
    description: "array order preserved",
    input: { arr: [3, 1, 2] },
    expected: '{"arr":[3,1,2]}',
  },
  {
    description: "null value",
    input: { x: null },
    expected: '{"x":null}',
  },
  {
    description: "undefined value skipped",
    input: { a: 1, b: undefined, c: 3 },
    expected: '{"a":1,"c":3}',
  },
  {
    description: "boolean values",
    input: { t: true, f: false },
    expected: '{"f":false,"t":true}',
  },
  {
    description: "unicode string",
    input: { msg: "hello 世界" },
    expected: '{"msg":"hello 世界"}',
  },
  {
    description: "string with quotes and backslash",
    input: { s: 'say "hi" \\here' },
    expected: '{"s":"say \\"hi\\" \\\\here"}',
  },
  {
    description: "full receipt-like object",
    input: {
      verb: "verify",
      version: "1.1.0",
      agent: "runtime.commandlayer.eth",
      payload: { input: "test", result: "ok" },
      timestamp: "2026-05-12T00:00:00.000Z",
    },
    expected:
      '{"agent":"runtime.commandlayer.eth","payload":{"input":"test","result":"ok"},"timestamp":"2026-05-12T00:00:00.000Z","verb":"verify","version":"1.1.0"}',
  },
  {
    // Mandatory audit test vector — protocol audit requires SHA-256 of this
    // canonical form to be computed and tested (see test/canonicalize.test.ts).
    // Input key insertion order is intentionally scrambled to verify sorting.
    description: "audit protocol vector: verb/family/version",
    input: { verb: "verify", family: "trust", version: "1.0.0" },
    expected: '{"family":"trust","verb":"verify","version":"1.0.0"}',
    // SHA-256 of the canonical string (UTF-8 encoded):
    sha256: "7f84cc113290c283fe97e3beb9bd3f65e5de0022e278cad25ef7619c398b1bab",
  },
] as const;
