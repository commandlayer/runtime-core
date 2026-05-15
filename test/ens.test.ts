/**
 * ENS resolution tests — runtime-core
 *
 * Uses an in-process mock provider — no network calls.
 * Tests both calling conventions (positional args and options object).
 */

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  resolveSignerFromENS,
  resolvePublicKeyFromENS,
  type EnsProvider,
  type EnsResolver,
} from "../src/ens.js";
import { encodePublicKey } from "../src/crypto.js";

// ── Mock provider factory ─────────────────────────────────────────────────────

function makeMockProvider(records: Record<string, string | null>): EnsProvider {
  const resolver: EnsResolver = {
    async getText(key: string): Promise<string | null> {
      return Object.prototype.hasOwnProperty.call(records, key)
        ? records[key]
        : null;
    },
  };
  return {
    async getResolver(_name: string): Promise<EnsResolver | null> {
      return resolver;
    },
  };
}

function makeNullProvider(): EnsProvider {
  return {
    async getResolver(_name: string): Promise<EnsResolver | null> {
      return null;
    },
  };
}

function makeThrowingProvider(): EnsProvider {
  return {
    async getResolver(_name: string): Promise<EnsResolver | null> {
      throw new Error("network timeout");
    },
  };
}

// ── Test helpers ──────────────────────────────────────────────────────────────

const RAW_KEY = new Uint8Array(32).fill(0xab);
const PUB_VALUE = encodePublicKey(RAW_KEY);
const RUNTIME_ENS_FIXTURE = {
  "cl.sig.kid": "vC4WbcNoq2znSCiQ",
  "cl.sig.pub": "ed25519:hhyCuPNoMk4JtEvGEV8F6nMZ4uDO1EcyizPufmnJTOY=",
  "cl.sig.canonical": "json.sorted_keys.v1",
  "cl.receipt.signer": "runtime.commandlayer.eth",
} as const;

const FULL_RECORDS: Record<string, string> = {
  "cl.sig.pub": PUB_VALUE,
  "cl.sig.kid": "testKid001",
  "cl.sig.canonical": "json.sorted_keys.v1",
};

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("resolveSignerFromENS — positional args", () => {
  it("parses runtime.commandlayer.eth TXT record shape fixture", async () => {
    const provider = makeMockProvider(RUNTIME_ENS_FIXTURE);
    const record = await resolveSignerFromENS("runtime.commandlayer.eth", provider);

    assert.strictEqual(record.kid, "vC4WbcNoq2znSCiQ");
    assert.strictEqual(record.canonical, "json.sorted_keys.v1");
    assert.strictEqual(record.rawPublicKey.length, 32);
  });

  it("resolves a full signer record", async () => {
    const provider = makeMockProvider(FULL_RECORDS);
    const record = await resolveSignerFromENS("test.commandlayer.eth", provider);

    assert.strictEqual(record.name, "test.commandlayer.eth");
    assert.deepStrictEqual(record.rawPublicKey, RAW_KEY);
    assert.strictEqual(record.kid, "testKid001");
    assert.strictEqual(record.canonical, "json.sorted_keys.v1");
  });

  it("defaults kid to empty string when cl.sig.kid is absent", async () => {
    const provider = makeMockProvider({ "cl.sig.pub": PUB_VALUE });
    const record = await resolveSignerFromENS("test.commandlayer.eth", provider);
    assert.strictEqual(record.kid, "");
  });

  it("defaults canonical to json.sorted_keys.v1 when absent", async () => {
    const provider = makeMockProvider({ "cl.sig.pub": PUB_VALUE });
    const record = await resolveSignerFromENS("test.commandlayer.eth", provider);
    assert.strictEqual(record.canonical, "json.sorted_keys.v1");
  });

  it("throws when no resolver found", async () => {
    const provider = makeNullProvider();
    await assert.rejects(
      () => resolveSignerFromENS("nobody.eth", provider),
      /No ENS resolver found/
    );
  });

  it("throws when provider errors", async () => {
    const provider = makeThrowingProvider();
    await assert.rejects(
      () => resolveSignerFromENS("test.eth", provider),
      /ENS resolution failed/
    );
  });

  it("throws when cl.sig.pub is missing", async () => {
    const provider = makeMockProvider({ "cl.sig.kid": "k1" });
    await assert.rejects(
      () => resolveSignerFromENS("test.eth", provider),
      /no cl.sig.pub text record/
    );
  });

  it("throws on unsupported canonical method", async () => {
    const provider = makeMockProvider({
      "cl.sig.pub": PUB_VALUE,
      "cl.sig.canonical": "sha256-sorted-v2",
    });
    await assert.rejects(
      () => resolveSignerFromENS("test.eth", provider),
      /unsupported canonical method/
    );
  });

  it("throws on malformed cl.sig.pub", async () => {
    const provider = makeMockProvider({ "cl.sig.pub": "notakey" });
    await assert.rejects(
      () => resolveSignerFromENS("test.eth", provider),
      /ed25519:/
    );
  });
});

describe("resolveSignerFromENS — options object form", () => {
  it("resolves using { ensName, provider } object", async () => {
    const provider = makeMockProvider(FULL_RECORDS);
    const record = await resolveSignerFromENS({
      ensName: "test.commandlayer.eth",
      provider,
    });
    assert.strictEqual(record.name, "test.commandlayer.eth");
    assert.deepStrictEqual(record.rawPublicKey, RAW_KEY);
  });

  it("throws when provider is missing from options", async () => {
    // TypeScript would catch this, but test runtime safety too
    await assert.rejects(
      async () => {
        const opts = { ensName: "test.eth" } as Parameters<typeof resolveSignerFromENS>[0];
        // Force the call through any cast to test runtime guard
        await (resolveSignerFromENS as (o: unknown) => Promise<unknown>)(opts);
      },
      /provider/
    );
  });
});

describe("resolveSignerFromENS — input validation", () => {
  it("throws on empty ensName string", async () => {
    const provider = makeMockProvider(FULL_RECORDS);
    await assert.rejects(
      () => resolveSignerFromENS("", provider),
      /ensName must be a non-empty string/
    );
  });

  it("throws when positional provider is missing", async () => {
    await assert.rejects(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      () => (resolveSignerFromENS as (n: string, p?: unknown) => Promise<unknown>)("test.eth", undefined),
      /provider is required/
    );
  });
});

describe("resolvePublicKeyFromENS", () => {
  it("returns the raw 32-byte public key", async () => {
    const provider = makeMockProvider(FULL_RECORDS);
    const key = await resolvePublicKeyFromENS("test.commandlayer.eth", provider);
    assert.deepStrictEqual(key, RAW_KEY);
    assert.strictEqual(key.length, 32);
  });

  it("also works with options object", async () => {
    const provider = makeMockProvider(FULL_RECORDS);
    const key = await resolvePublicKeyFromENS({
      ensName: "test.commandlayer.eth",
      provider,
    });
    assert.deepStrictEqual(key, RAW_KEY);
  });
});
