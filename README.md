# @commandlayer/runtime-core

Canonical crypto and receipt verification primitives for CommandLayer CLAS.

## Installation

Install from npm (not GitHub tarball/git dependency):

```bash
npm install @commandlayer/runtime-core@1.2.0
```

## Canonical proof envelope (CLAS)

`signCommandLayerReceipt()` writes the legacy/single-proof canonical envelope:

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
```

This surface remains for backward compatibility. New `clas.execution.receipt.v1` receipts use the strict scoped-proof API below.

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

## Strict CLAS scoped execution and settlement proofs

The canonical `clas.execution.receipt.v1` proof shape follows the CLAS execution schema:

```json
{
  "type": "execution",
  "covers": ["receipt_id", "verb", "agent", "action"],
  "signer": "exampleagent.eth",
  "canonicalization": "json.sorted_keys.v1",
  "signature": {
    "alg": "Ed25519",
    "kid": "execution-kid",
    "value": "..."
  }
}
```

Important compatibility boundary:

- canonical CLAS scoped proofs keep `signer` **top-level**;
- canonical CLAS scoped proofs do **not** contain a separate `hash` field;
- the Ed25519 signature is over the raw UTF-8 bytes of the canonical covered payload;
- execution coverage is exactly `["receipt_id", "verb", "agent", "action"]`;
- settlement coverage is exactly `["receipt_id", "settlement"]`.

Runtime-core owns both strict signing and strict verification so downstream applications do not reimplement canonicalization or crypto.

```ts
import {
  signExecutionScopedProof,
  signSettlementScopedProof,
  verifyClasScopedProofs,
} from "@commandlayer/runtime-core";

const executionSigned = signExecutionScopedProof(receipt, {
  privateKeyPem: executionPrivateKey,
  kid: "execution-kid",
  signer: "exampleagent.eth",
});

const fullySigned = signSettlementScopedProof(executionSigned, {
  privateKeyPem: settlementPrivateKey,
  kid: "settlement-kid",
  signer: "settlement:provider",
});

const result = verifyClasScopedProofs(fullySigned, {
  publicKeysByKid: {
    "execution-kid": executionPublicKey,
    "settlement-kid": settlementPublicKey,
  },
});
```

`signExecutionScopedProof()` cannot include settlement fields because runtime-core chooses proof coverage. `signSettlementScopedProof()` fails when the receipt has no settlement object. Both return a new receipt rather than mutating the input.

`verifyClasScopedProofs()` is the strict verifier for new CLAS execution receipts. The older `verifyScopedProofs()` export remains available only as a compatibility surface for pre-schema/hash-bearing scoped proofs and should not be used to generate or define new receipt formats.

A settlement object requires a valid settlement proof. Tampering action fields invalidates the execution proof without invalidating settlement proof, and tampering settlement fields invalidates settlement proof without changing the execution proof.
