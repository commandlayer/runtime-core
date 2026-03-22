# @commandlayer/runtime-core

Core contract primitives for the CommandLayer v1.1.0 current line.

This package now models the two current-line contract families explicitly:

- **Commons**: request/receipt payloads with no x402 or payment metadata assumptions.
- **Commercial**: the same execution contract plus an explicit `commercial` metadata object for payment-aware runtimes.

Legacy 1.0.0 helpers are still exported, but they are isolated and labeled as legacy bridges.

## What it provides

- Current-line request normalization for Commons and Commercial flows
- Current-line receipt builders, canonicalization, signing, and verification helpers
- Explicit schema path helpers for the v1.1.0 split between Commons and Commercial
- ENS signer discovery from TXT records
- Legacy 1.0.0 receipt verification bridges for `metadata.proof` and `ed25519-sha256`
- Compact AJV error formatting

## Install

```bash
npm install @commandlayer/runtime-core
```

## Current-line usage

### Normalize Commons and Commercial requests

```ts
import {
  normalizeCommonsRequest,
  normalizeCommercialRequest
} from '@commandlayer/runtime-core';

const commons = normalizeCommonsRequest({
  trace: { request_id: 'req_1' },
  payload: { message: 'hello' }
});

const commercial = normalizeCommercialRequest({
  trace: { request_id: 'req_2' },
  payload: { message: 'hello' },
  commercial: { plan: 'pro', settlement: 'required' }
});
```

### Resolve current-line schema URLs

```ts
import {
  buildSchemaPath,
  COMMAND_LAYER_CURRENT_LINE,
  COMMONS_CONTRACT,
  COMMERCIAL_CONTRACT,
  createSchemaClient
} from '@commandlayer/runtime-core';

buildSchemaPath({
  contract: COMMONS_CONTRACT,
  verb: 'chat.completions',
  kind: 'request'
});
// /schemas/1.1.0/commons/chat.completions/v1/request.schema.json

const schemas = createSchemaClient({
  schemaHost: 'https://schemas.commandlayer.io',
  lineVersion: COMMAND_LAYER_CURRENT_LINE
});

const validateCommercialReceipt = await schemas.getReceiptValidator({
  contract: COMMERCIAL_CONTRACT,
  verb: 'chat.completions',
  version: 'v1'
});
```

### Build, sign, and verify current-line receipts

```ts
import {
  buildCommonsReceipt,
  buildCommercialReceipt,
  canonicalizeReceipt,
  createLayeredReceipt,
  hashReceiptCanonical,
  signReceiptEd25519,
  verifyReceiptSignature
} from '@commandlayer/runtime-core';

const commonsReceipt = buildCommonsReceipt({
  verb: 'chat.completions',
  version: 'v1',
  trace: { request_id: 'req_1' },
  payload: { prompt: 'hello' },
  status: 'ok',
  result: { output: 'world' }
});

const commercialReceipt = buildCommercialReceipt({
  verb: 'chat.completions',
  version: 'v1',
  trace: { request_id: 'req_2' },
  payload: { prompt: 'hello' },
  commercial: { plan: 'pro', settlement: 'required' },
  status: 'ok',
  result: { output: 'world' }
});

const canonical = canonicalizeReceipt(commercialReceipt);
const hash = hashReceiptCanonical(canonical);

const signed = signReceiptEd25519(commercialReceipt, {
  privateKey: process.env.SIGNING_PRIVATE_KEY_PEM!,
  signer_id: 'signer.commandlayer.eth',
  kid: '2026-01'
});

const layered = createLayeredReceipt(commonsReceipt, {
  execution: { duration_ms: 42 }
});

const ok = verifyReceiptSignature(signed, {
  pubkey: process.env.SIGNING_PUBLIC_KEY_PEM!
});
```

`receipt` remains the canonical signed payload. Runtime metadata and signatures stay layered outside the receipt body.

### Resolve signer from ENS

```ts
import { JsonRpcProvider } from 'ethers';
import { resolveSignerFromENS } from '@commandlayer/runtime-core';

const provider = new JsonRpcProvider(process.env.RPC_URL);
const signer = await resolveSignerFromENS({
  ensName: 'signer.commandlayer.eth',
  provider
});
```

Supported TXT records:

- Preferred: `cl.sig.pub = ed25519:<base64url_raw32>`
- Optional: `cl.sig.kid`, `cl.sig.canonical`
- Legacy fallback: `cl.receipt.pubkey.pem`

## Legacy 1.0.0 bridge

If you still need old `metadata.proof` envelopes or `ed25519-sha256` receipts, import the isolated compatibility helpers:

```ts
import {
  signReceiptEd25519Sha256,
  toLegacyReceiptEnvelope,
  verifyReceiptEd25519Sha256
} from '@commandlayer/runtime-core/receipt-v1';
```

These are explicitly legacy APIs and should not be used for new current-line Commons or Commercial flows.

## Development

```bash
npm run build
npm test
```
