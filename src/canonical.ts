/**
 * Canonicalization: json.sorted_keys.v1
 * - Deterministic, recursive key ordering
 * - JSON.stringify on the normalized structure
 *
 * This is intentionally simple and stable; we treat the canonical string as the
 * signing input after hashing (sha256 hex), consistent across runtimes.
 */

export const CANONICAL_ID_SORTED_KEYS_V1 = "json.sorted_keys.v1";

type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [k: string]: Json };

function isPlainObject(v: any): v is Record<string, any> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function normalize(v: any): Json {
  if (v === null) return null;
  const t = typeof v;

  if (t === "string" || t === "boolean") return v;
  if (t === "number") {
    // JSON doesn't support NaN/Infinity; encode as null to avoid nondeterminism
    return Number.isFinite(v) ? v : null;
  }

  if (Array.isArray(v)) return v.map(normalize);

  if (isPlainObject(v)) {
    const out: Record<string, Json> = {};
    const keys = Object.keys(v).sort();
    for (const k of keys) out[k] = normalize(v[k]);
    return out;
  }

  // Unsupported types: map to string to avoid throwing during canonicalization
  // (runtimes should validate before signing anyway)
  return String(v) as any;
}

/** Return canonical JSON string per json.sorted_keys.v1 */
export function canonicalizeSortedKeysV1(value: any): string {
  const normalized = normalize(value);
  return JSON.stringify(normalized);
}
