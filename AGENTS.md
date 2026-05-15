# CommandLayer Repository Instructions

This repository is part of the CommandLayer protocol stack.

## Repo role

`commandlayer/runtime-core` is the canonical crypto and receipt verification primitive library for CommandLayer.

This repository owns:

- deterministic canonicalization primitives
- SHA-256 hashing primitives
- Ed25519 signing and verification primitives
- receipt proof verification helpers
- crypto-focused test vectors
- local validation utilities for receipt proof integrity

This repository does not own runtime execution, hosted APIs, web UI, registry pages, MCP transport behavior, commercial flows, or website documentation.

## Hard rules

- Do not guess.
- Do not publish packages.
- Do not merge pull requests.
- Do not introduce network calls into core verification primitives.
- Do not introduce runtime execution logic.
- Do not introduce website, UI, or demo app code.
- Do not mock, skip, simulate, or weaken Ed25519 verification.
- Do not change canonicalization behavior without test vectors and compatibility notes.
- Do not change public APIs without documenting impact.
- Do not introduce placeholders, TODOs, skipped tests, or hardcoded secrets.
- Do not invent implementation status.
- Do not change receipt semantics without referencing the CLAS stack contract.

## Protocol requirements

Runtime-core behavior MUST align with the canonical stack contract in `commandlayer/clas`:

- canonicalization ID: `json.sorted_keys.v1`
- hash algorithm: SHA-256
- signature algorithm: Ed25519
- hash values: lowercase hexadecimal unless a schema version says otherwise
- verification: fail closed on invalid hash, invalid signature, malformed proof, unsupported algorithm, or signer mismatch

## Before editing

1. Inspect `package.json`, `README.md`, `src`, `test`, `.env.example`, and exported API files.
2. Identify whether the change affects canonicalization, hashing, signing, verification, compatibility, docs, or package metadata.
3. Compare the change against the CLAS stack contract.
4. Make the smallest safe change.
5. Run build, test, typecheck, and lint commands if available.
6. Report changed files, commands run, results, and remaining risks.

## Crypto rules

- Ed25519 verification MUST be real.
- SHA-256 hashing MUST be deterministic and tested.
- Canonicalization MUST sort object keys recursively.
- Canonicalization MUST preserve JSON value semantics.
- Verification MUST fail closed.
- Public key resolution helpers MAY be exposed only if they do not force network calls into core primitives.
- Production public keys MUST NOT be hardcoded as the only verification path.

## Test requirements

Changes to canonicalization, hashing, signing, or verification SHOULD include tests for:

- valid receipt proof verification
- tampered payload failure
- tampered signature failure
- canonical key ordering
- nested object canonicalization
- SHA-256 known vectors
- unsupported algorithm failure
- missing required proof fields

## Review focus

When reviewing changes, focus on:

- mocked verification
- skipped tests
- accidental network dependencies
- non-deterministic canonicalization
- public API drift
- receipt proof field mismatch
- README claims not backed by exported code
- unused dependencies
- hardcoded secrets or keys
- compatibility drift from CLAS

## Output format

For every task, report:

1. Summary
2. Files changed
3. Checks run
4. Results
5. Risks remaining
6. Follow-up recommendations
