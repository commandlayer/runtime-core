import { createHash } from "node:crypto";
import { canonicalize } from "./canonicalize.js";

/** SHA-256 a UTF-8 string and return the protocol wire form. */
export function sha256Text(value: string): string {
  if (typeof value !== "string") throw new TypeError("value must be a string");
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

/** Canonicalize a JSON-compatible value with json.sorted_keys.v1, then SHA-256 it. */
export function hashCanonical(value: unknown): string {
  return sha256Text(canonicalize(value));
}
