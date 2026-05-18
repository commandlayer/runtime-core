# @commandlayer/runtime-core

Canonical crypto and receipt verification primitives for CommandLayer CLAS.

## Installation

Install from npm (not GitHub tarball/git dependency):

```bash
npm install @commandlayer/runtime-core@1.2.0
```

## Canonical proof envelope (CLAS)

`signCommandLayerReceipt()` writes the canonical proof envelope:

- `metadata.proof.canonicalization = "json.sorted_keys.v1"`
- `metadata.proof.hash.alg = "SHA-256"`
- `metadata.proof.hash.value = <lowercase hex digest>`
- `metadata.proof.signature.alg = "Ed25519"`
- `metadata.proof.signature.value = <base64 signature>`
- `metadata.proof.signature.kid = <required key id>`

```ts
import { signCommandLayerReceipt, verifyCommandLayerReceipt } from "@commandlayer/runtime-core";

const signed = signCommandLayerReceipt(receipt, { privateKeyPem, kid: "vC4WbcNoq2znSCiQ" });
const result = verifyCommandLayerReceipt(signed, { publicKeyPemOrDer: publicKeyPem });

// result shape
// {
//   ok: boolean,
//   status: "VERIFIED" | "INVALID",
//   checks: { schema, canonical_hash, signature, signer },
//   errors: string[]
// }
```

## ENS signer records

Supported signer TXT records:

- `cl.sig.pub = ed25519:<base64-raw-public-key>`
- `cl.sig.kid = <kid>`
- `cl.sig.canonical = json.sorted_keys.v1`
- `cl.receipt.signer = <signer ENS identity>`

Example fixture:

- `cl.sig.kid = vC4WbcNoq2znSCiQ`
- `cl.sig.pub = ed25519:hhyCuPNoMk4JtEvGEV8F6nMZ4uDO1EcyizPufmnJTOY=`
- `cl.sig.canonical = json.sorted_keys.v1`
- `cl.receipt.signer = runtime.commandlayer.eth`

When `ensRecord` is provided to `verifyCommandLayerReceipt`, verifier compares:

- `signature.kid` ↔ `cl.sig.kid`
- `metadata.proof.canonicalization` ↔ `cl.sig.canonical`
- `receipt.agent` ↔ `cl.receipt.signer`

## Endpoint discovery metadata (optional)

ENS resolver also parses optional discovery TXT records:

- `cl.endpoint.runtime`
- `cl.endpoint.verify`
- `cl.endpoint.mcp`
- `cl.endpoint.docs`
- `cl.endpoint.registry`

These endpoint records are **optional discovery metadata only** and are **not verification-critical proof**.

## Development

```bash
npm install
npm run build
npm test
npm run typecheck
```
