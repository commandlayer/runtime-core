/**
 * Canonicalization: json.sorted_keys.v1
 * - Deterministic, recursive key ordering
 * - JSON.stringify on the normalized structure
 *
 * This is intentionally simple and stable; we treat the canonical string as the
 * signing input after hashing (sha256 hex), consistent across runtimes.
 */
export declare const CANONICAL_ID_SORTED_KEYS_V1 = "json.sorted_keys.v1";
/** Return canonical JSON string per json.sorted_keys.v1 */
export declare function canonicalizeSortedKeysV1(value: any): string;
//# sourceMappingURL=canonical.d.ts.map