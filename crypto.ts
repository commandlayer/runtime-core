/**
 * @commandlayer/runtime-core — crypto.ts
 *
 * PROTOCOL SIGNING CONTRACT (canonical, locked to ENS production record):
 *   cl.sig.canonical = json.sorted_keys.v1
 *   cl.sig.pub       = ed25519:<standard_base64_raw32>   (= padding, +/ charset)
 *   signing message  = Ed25519.sign(raw_canonical_utf8_bytes)
 *                      where canonical = canonicalizeSortedKeysV1(payload)
 *
 * DO NOT change the signing message without a protocol version bump and
 * coordinated migration across all repos.
 */

import { createSign, createVerify, generateKeyPairSync } from "node:crypto";

// ── Protocol constants ────────────────────────────────────────────────────────

export const PROTOCOL_VERSION = "1.1.0" as const;
export const CANONICAL_METHOD = "json.sorted_keys.v1" as const;
export const SIGNATURE_ALG = "ed25519" as const;

/** The ENS text record key for the signer's public key. */
export const ENS_KEY_PUB = "cl.sig.pub" as const;
export const ENS_KEY_KID = "cl.sig.kid" as const;
export const ENS_KEY_CANONICAL = "cl.sig.canonical" as const;
export const ENS_KEY_SIGNER = "cl.receipt.signer" as const;

// ── Key encoding (standard base64, matches production ENS records) ────────────

/**
 * Encode a raw 32-byte Ed25519 public key to the ENS cl.sig.pub format:
 *   ed25519:<standard_base64>
 *
 * Standard base64: uses A-Z a-z 0-9 +/ with = padding.
 * This matches the live ENS record for runtime.commandlayer.eth.
 */
export function encodePublicKey(rawBytes: Uint8Array): string {
  if (rawBytes.length !== 32) {
    throw new Error(
      `Ed25519 public key must be 32 bytes, got ${rawBytes.length}`
    );
  }
  return `ed25519:${Buffer.from(rawBytes).toString("base64")}`;
}

/**
 * Parse an ENS cl.sig.pub value to raw 32-byte public key.
 * Accepts: ed25519:<standard_base64>
 * Rejects anything that isn't 32 bytes after decode.
 */
export function parsePublicKey(ensPubValue: string): Uint8Array {
  const prefix = "ed25519:";
  if (!ensPubValue.startsWith(prefix)) {
    throw new Error(
      `cl.sig.pub must start with "ed25519:", got: ${ensPubValue.slice(0, 20)}`
    );
  }
  const b64 = ensPubValue.slice(prefix.length);
  const raw = Buffer.from(b64, "base64");
  if (raw.length !== 32) {
    throw new Error(
      `cl.sig.pub decoded to ${raw.length} bytes; expected 32 (Ed25519 public key)`
    );
  }
  return new Uint8Array(raw);
}

// ── Signing ───────────────────────────────────────────────────────────────────

/**
 * Sign a canonical string using an Ed25519 private key (PEM or DER).
 *
 * Signing message: raw UTF-8 bytes of the canonical string.
 * NOT sha256(canonical) — signs the data directly.
 *
 * Returns: standard base64-encoded 64-byte signature.
 */
export function signCanonical(
  canonicalString: string,
  privateKeyPem: string
): string {
  const sign = createSign("Ed25519");
  sign.update(canonicalString, "utf8");
  sign.end();
  const sigBuffer = sign.sign(privateKeyPem);
  if (sigBuffer.length !== 64) {
    throw new Error(
      `Ed25519 signature must be 64 bytes, got ${sigBuffer.length}`
    );
  }
  return sigBuffer.toString("base64");
}

/**
 * Verify an Ed25519 signature over a canonical string.
 *
 * @param canonicalString  The canonical JSON string that was signed
 * @param signatureBase64  Standard base64-encoded signature (64 bytes)
 * @param publicKeyPem     PEM-encoded Ed25519 public key
 *
 * Returns true if signature is valid, false otherwise.
 * Never throws on invalid signature — only throws on malformed inputs.
 */
export function verifyCanonical(
  canonicalString: string,
  signatureBase64: string,
  publicKeyPem: string
): boolean {
  const sigBuffer = Buffer.from(signatureBase64, "base64");
  if (sigBuffer.length !== 64) {
    throw new Error(
      `Signature must decode to 64 bytes (Ed25519), got ${sigBuffer.length}`
    );
  }
  try {
    const verify = createVerify("Ed25519");
    verify.update(canonicalString, "utf8");
    verify.end();
    return verify.verify(publicKeyPem, sigBuffer);
  } catch {
    return false;
  }
}

/**
 * Verify using a raw 32-byte public key (from ENS cl.sig.pub).
 * Converts to PEM internally then delegates to verifyCanonical.
 */
export function verifyCanonicalWithRawKey(
  canonicalString: string,
  signatureBase64: string,
  rawPublicKey: Uint8Array
): boolean {
  if (rawPublicKey.length !== 32) {
    throw new Error(
      `Raw public key must be 32 bytes, got ${rawPublicKey.length}`
    );
  }
  // Wrap raw key in SubjectPublicKeyInfo DER for node:crypto
  // Ed25519 SPKI prefix: 302a300506032b6570032100
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const spkiDer = Buffer.concat([spkiPrefix, Buffer.from(rawPublicKey)]);
  const pem = `-----BEGIN PUBLIC KEY-----\n${spkiDer
    .toString("base64")
    .match(/.{1,64}/g)!
    .join("\n")}\n-----END PUBLIC KEY-----`;
  return verifyCanonical(canonicalString, signatureBase64, pem);
}

// ── Key generation (for testing / provisioning) ───────────────────────────────

export interface Ed25519KeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
  /** Raw 32-byte public key, ready for ENS cl.sig.pub encoding */
  rawPublicKey: Uint8Array;
  /** Formatted ENS cl.sig.pub value */
  ensPubValue: string;
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  // Extract raw 32-byte public key from SPKI PEM
  const spkiDer = Buffer.from(
    (publicKey as string)
      .replace(/-----[^-]+-----/g, "")
      .replace(/\s/g, ""),
    "base64"
  );
  // Last 32 bytes of SPKI DER are the raw Ed25519 key
  const rawPublicKey = new Uint8Array(spkiDer.slice(-32));

  return {
    privateKeyPem: privateKey as string,
    publicKeyPem: publicKey as string,
    rawPublicKey,
    ensPubValue: encodePublicKey(rawPublicKey),
  };
}
