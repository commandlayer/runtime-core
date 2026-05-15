# @commandlayer/runtime-core

Core signing, verification, and canonicalization primitives for the CommandLayer v1.1.0 protocol.

This package is the single canonical implementation of:

- **Canonicalization** — `json.sorted_keys.v1` deterministic JSON (keys sorted at every level)
- **Ed25519 signing and verification** — real `node:crypto` Ed25519, no mocks
- **Signed layered receipts** — v1.1.0 `SignedLayeredReceipt` with structured proof envelope
- **ENS signer resolution** — live TXT record lookup for `cl.sig.pub`
- **Legacy compat shims** — `metadata.proof` envelope bridge for runtime/server.mjs

All other CommandLayer repos import from here. Nothing is reimplemented downstream.

## Install

```bash
npm install @commandlayer/runtime-core
```

Requires Node.js >= 20.

## Usage

### Canonicalization

```ts
import { canonicalize } from '@commandlayer/runtime-core';

const canonical = canonicalize({
  verb: 'chat.completions',
  version: '1.1.0',
  agent: 'runtime.commandlayer.eth',
  timestamp: '2026-05-12T00:00:00.000Z',
});
// Keys are sorted at every level, no trailing whitespace, no undefined values
```

### Sign and verify a receipt

```ts
import {
  generateEd25519KeyPair,
  signReceipt,
  verifyReceipt,
} from '@commandlayer/runtime-core';

const { privateKeyPem, rawPublicKey } = generateEd25519KeyPair();

const signed = signReceipt(
  {
    verb: 'chat.completions',
    version: '1.1.0',
    agent: 'runtime.commandlayer.eth',
    timestamp: new Date().toISOString(),
    payload: { prompt: 'hello' },
    result: { output: 'world' },
  },
  {
    privateKeyPem,
    kid: process.env.KEY_ID!,
    signerEns: 'runtime.commandlayer.eth',
  }
);

const result = verifyReceipt(signed, {
  rawPublicKey,
  expectedSigner: 'runtime.commandlayer.eth',
});

console.assert(result.valid === true);
```

### Resolve signer from ENS

```ts
import { JsonRpcProvider } from 'ethers';
import { resolveSignerFromENS } from '@commandlayer/runtime-core';

// Positional form
const provider = new JsonRpcProvider(process.env.RPC_URL);
const signer = await resolveSignerFromENS('signer.commandlayer.eth', provider);

// Options-object form (equivalent)
const signer2 = await resolveSignerFromENS({
  ensName: 'signer.commandlayer.eth',
  provider,
});
```

Supported TXT records:

| Key | Required | Description |
|-----|----------|-------------|
| `cl.sig.pub` | Yes | `ed25519:<standard_base64_raw32>` |
| `cl.sig.kid` | No | Short key identifier |
| `cl.sig.canonical` | No | Defaults to `json.sorted_keys.v1` |

### Key encoding

```ts
import { encodePublicKey, parsePublicKey } from '@commandlayer/runtime-core';

// Encode raw 32-byte key for ENS TXT record
const ensValue = encodePublicKey(rawPublicKey);
// => "ed25519:hhyCuPNoMk4JtEvGEV8F6nMZ4uDO1EcyizPufmnJTOY="

// Parse ENS TXT record back to raw bytes
const raw = parsePublicKey(ensValue);
// => Uint8Array(32)
```

### Low-level crypto

```ts
import {
  canonicalize,
  signCanonical,
  verifyCanonical,
  verifyCanonicalWithRawKey,
} from '@commandlayer/runtime-core';

const canonical = canonicalize(payload);
const signature = signCanonical(canonical, privateKeyPem);
const valid = verifyCanonical(canonical, signature, publicKeyPem);
const validFromRaw = verifyCanonicalWithRawKey(canonical, signature, rawPublicKey);
```

### Canonical CLAS proof envelope

Use the canonical metadata proof API:

```ts
import {
  signCommandLayerReceipt,
  verifyCommandLayerReceipt,
  buildCanonicalProof,
  isSignedCommandLayerReceipt,
} from '@commandlayer/runtime-core';
```

Canonical envelope fields:
- `metadata.proof.canonicalization`
- `metadata.proof.hash.alg`
- `metadata.proof.hash.value`
- `metadata.proof.signature.alg`
- `metadata.proof.signature.value`
- `metadata.proof.signature.kid`

### Cross-repo canonicalization alignment

Every repo that imports `@commandlayer/runtime-core` should run the shared test vectors:

```ts
import { canonicalize, CANONICAL_TEST_VECTORS } from '@commandlayer/runtime-core';

for (const { description, input, expected } of CANONICAL_TEST_VECTORS) {
  const actual = canonicalize(input);
  if (actual !== expected) throw new Error(`Vector failed: ${description}`);
}
```

## Protocol constants

```ts
import {
  PROTOCOL_VERSION,   // "1.1.0"
  CANONICAL_METHOD,   // "json.sorted_keys.v1"
  SIGNATURE_ALG,      // "ed25519"
  ENS_KEY_PUB,        // "cl.sig.pub"
  ENS_KEY_KID,        // "cl.sig.kid"
  ENS_KEY_CANONICAL,  // "cl.sig.canonical"
  ENS_KEY_SIGNER,     // "cl.receipt.signer"
} from '@commandlayer/runtime-core';
```

## Environment variables

See `.env.example` for the full list. Key variables:

| Variable | Used by | Description |
|----------|---------|-------------|
| `RPC_URL` | `resolveSignerFromENS` | Ethereum JSON-RPC endpoint |
| `SIGNING_PRIVATE_KEY_PEM` | `signReceipt`, `signCanonical` | Ed25519 private key (PEM) |
| `SIGNING_PUBLIC_KEY_PEM` | `verifyReceipt`, `verifyCanonical` | Ed25519 public key (PEM) |
| `SIGNER_ENS_NAME` | ENS | ENS name with `cl.sig.pub` set |

## Development

```bash
npm run build   # compile TypeScript
npm test        # run all tests
npm run typecheck  # type-check without emitting
```

## Signing protocol

The signing message is **raw UTF-8 bytes** of `canonicalize(receipt)`. This is NOT `sha256(canonical)` — signatures are over the data directly. Any change to this contract requires a protocol version bump.

```
signature = Ed25519.sign(
  privateKey,
  UTF8(canonicalize(receiptPayload))
)
```

## License

Apache-2.0
