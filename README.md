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

## CLAS scoped execution and settlement proofs

`clas.execution.receipt.v1` receipts may contain `proofs[]` with multiple attestations over different receipt slices:

Private settlement, public accountability.
The agent signs execution.
The settlement rail or payer signs settlement.
The shared receipt_id binds both attestations into one receipt.

Runtime-core verifies scoped proofs with the existing `json.sorted_keys.v1` canonicalization. `buildCoveredPayload(receipt, proof)` first materializes only the top-level fields listed by `proof.covers[]`, then canonicalizes that covered payload with recursively sorted object keys before SHA-256 hashing and Ed25519 verification.

Coverage is intentionally exact and ordered to match CLAS examples:

- execution proofs must use `covers: ["receipt_id", "verb", "agent", "action"]`
- settlement proofs must use `covers: ["receipt_id", "settlement"]`

A settlement object requires a valid settlement proof. Tampering settlement fields invalidates only the settlement proof, while execution proofs remain scoped to execution fields. Existing `metadata.proof` verification remains available through `verifyCommandLayerReceipt()` for older single-proof receipts.
