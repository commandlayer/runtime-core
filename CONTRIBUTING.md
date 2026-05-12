# Contributing — @commandlayer/runtime-core

## Protocol First

This repo is the canonical implementation of the CommandLayer protocol.
Every function here is imported by other repos — it is not an app, it is a spec in code.

Before adding or changing anything:
1. Read `PROTOCOL.md` in commandlayer-org
2. Confirm the change is consistent with the protocol specification
3. If the change would affect signing, verification, or canonicalization — it is a breaking change requiring a protocol version bump

## Development

```bash
git clone https://github.com/commandlayer/runtime-core
cd runtime-core
npm install
npm run build
npm test
```

## Rules

- **No new crypto implementations** — everything signs using `signCanonical` in `crypto.ts`
- **No new canonicalize functions** — everything canonicalizes using `canonicalize` in `canonicalize.ts`
- **No new ENS parsers** — everything resolves using `resolveSignerFromENS` in `ens.ts`
- **Test vectors must stay passing** — `CANONICAL_TEST_VECTORS` are imported by other repos; breaking them is an ecosystem-wide breakage
- **Proof field names are locked** — `alg`, `kid`, `signer_id`, `canonical`, `signature`. Not `signature_alg`, `key_id`, `signer`. The schema enforces this.

## Pull Requests

- All PRs require CI passing (build + test + type check)
- Breaking changes require a CHANGELOG entry and a version bump
- PRs that change `crypto.ts` or `canonicalize.ts` require sign-off from a maintainer

## Publishing

Publishing to npm is done from CI after tagging a release.
Do not `npm publish` manually.
