# @commandlayer/runtime-core

Shared protocol engine for CommandLayer runtimes. This package centralizes the request/receipt contract used by both open and commercial runtime tiers so receipts remain verifiable by the same rules.

## What it provides

- Request normalization (`payload` plus legacy `input` support)
- JSON-schema validation client (AJV + remote schema loading)
- Receipt build/canonicalize/hash/sign/verify helpers
- ENS signer discovery from TXT records
- Compact AJV error formatting

## Install

```bash
npm install @commandlayer/runtime-core
```

## Usage

### Normalize request

```ts
import { normalizeRequest } from '@commandlayer/runtime-core';

const normalized = normalizeRequest({
  x402: { plan: 'pro' },
  trace: { id: 't-123' },
  input: { message: 'hello' } // legacy alias
});

// => { x402, trace, payload }
```

### Validate request/receipt schemas

```ts
import { createSchemaClient, formatAjvErrors } from '@commandlayer/runtime-core';

const schemas = createSchemaClient({
  schemaHost: 'https://schemas.commandlayer.io',
  timeoutMs: 5000
});

const validateRequest = await schemas.getRequestValidator({
  tier: 'commercial',
  verb: 'chat.completions',
  version: 'v1'
});

const isValid = validateRequest({ payload: { message: 'hi' } });
if (!isValid) {
  console.error(formatAjvErrors(validateRequest.errors));
}
```

### Build, sign, and verify receipts

```ts
import {
  buildUnsignedReceipt,
  canonicalizeReceipt,
  hashReceiptCanonical,
  signReceiptEd25519,
  verifyReceiptSignature
} from '@commandlayer/runtime-core';

const unsigned = buildUnsignedReceipt({
  verb: 'chat.completions',
  version: 'v1',
  x402: { policy: 'standard' },
  trace: { request_id: 'req_1' },
  payload: { prompt: 'hello' },
  status: 'ok',
  result: { output: 'world' }
});

const canonical = canonicalizeReceipt(unsigned);
const hash = hashReceiptCanonical(canonical); // sha256 bytes

const signed = signReceiptEd25519(unsigned, {
  privateKey: process.env.SIGNING_PRIVATE_KEY_PEM!,
  signer_id: 'signer.commandlayer.eth',
  kid: '2026-01',
  canonical: 'json.sorted_keys.v1'
});

const ok = verifyReceiptSignature(signed, {
  pubkey: process.env.SIGNING_PUBLIC_KEY_PEM!,
  canonical: 'json.sorted_keys.v1'
});
```

### Resolve signer from ENS

```ts
import { JsonRpcProvider } from 'ethers';
import { resolveSignerFromENS } from '@commandlayer/runtime-core';

const provider = new JsonRpcProvider(process.env.RPC_URL);
const signer = await resolveSignerFromENS({
  ensName: 'signer.commandlayer.eth',
  provider
});

// signer.pubkeyRaw32 / signer.pubkeyEncoded / signer.kid / signer.canonical
```

Supported TXT records:

- Preferred: `cl.sig.pub = ed25519:<base64url_raw32>`
- Optional: `cl.sig.kid`, `cl.sig.canonical`
- Fallback: `cl.receipt.pubkey.pem` (SPKI PEM, Ed25519 public key)

## Publish

```bash
npm ci
npm test
npm pack
npm publish --access public
```

## Development

```bash
npm run build
npm test
```
