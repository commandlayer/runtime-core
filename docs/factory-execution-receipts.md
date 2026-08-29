# Machine-Service Factory execution receipt profile

`commandlayer.execution-evidence.v1` is the rail-neutral execution receipt profile used by the CommandLayer Machine-Service Factory.

It deliberately does not require ENS, ERC-8004, x402, settlement payloads, stealth addresses, or any other identity/payment adapter. Those systems may be attached outside the signed execution evidence boundary.

The signed payload covers exactly:

- `receipt_id`
- `profile`
- `issued_at`
- `service`
- `execution`

The proof shape is:

```json
{
  "type": "execution",
  "covers": ["receipt_id", "profile", "issued_at", "service", "execution"],
  "signer": "commandlayer:factory:example",
  "canonicalization": "json.sorted_keys.v1",
  "signature": {
    "alg": "Ed25519",
    "kid": "example-key-id",
    "value": "..."
  }
}
```

Runtime-core signs the canonical covered payload directly with Ed25519. No redundant scoped hash field is emitted.

## Trust boundary

A valid factory receipt establishes cryptographic integrity and provenance for the covered execution envelope. It can prove what service/version ran, the execution identifier, and the execution evidence that was signed. It does not prove that a provider's underlying observation or model output is factually correct.

## Key resolution

Verification is registry-neutral. Callers can provide:

- one public key;
- a `kid -> public key` map; or
- a resolver callback.

ENS, DID, HTTPS/JWKS, ERC-8004 or another registry can therefore be used as a key-discovery adapter without becoming a receipt prerequisite.

## CLAS relationship

The existing `clas.execution.receipt.v1` strict scoped-proof implementation remains supported as a specialized profile. It is not the universal Machine-Service Factory receipt because the current CLAS execution schema includes deployment-specific identity/settlement requirements tracked in `commandlayer/clas#39`.
