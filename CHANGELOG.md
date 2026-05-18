# Changelog — @commandlayer/runtime-core

All notable changes to this package are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.2.0] — 2026-05-18

### Changed

- Declared npm publication readiness for `@commandlayer/runtime-core` with release metadata aligned to `dist/` exports and packaged artifacts.
- Canonical CLAS proof envelope documentation now explicitly tracks:
  - `metadata.proof.canonicalization = "json.sorted_keys.v1"`
  - `metadata.proof.hash.alg = "SHA-256"`
  - `metadata.proof.signature.alg = "Ed25519"` (with legacy lowercase verification compatibility only)
- README installation guidance now points to npm package installs rather than GitHub git/tarball installs.

### Notes

- This release is a **minor bump** (1.1.0 → 1.2.0) because it preserves current public runtime behavior while formalizing release packaging and documentation for downstream consumption.
- A major bump (`2.0.0`) is not required here because no additional breaking API change is introduced beyond the already-landed 1.1.0 breaking changes.

---

## [1.1.0] — 2026-05-12

### Breaking Changes

- **Signing message changed to raw canonical bytes** (was: sha256 hex string in some implementations).
  The protocol now formally specifies: `Ed25519.sign(raw_utf8_bytes_of_canonicalize(payload))`.
  Any verifier that was checking `Ed25519.verify(sha256_hex_string, sig, key)` must update.

- **ENS public key encoding is now standard base64** with `=` padding (A-Z a-z 0-9 +/).
  Format: `ed25519:<standard_base64_raw32>`.
  This matches the production ENS record for `runtime.commandlayer.eth`.
  Any code parsing base64url-encoded keys must update.

- **Proof field names corrected** to match clas schema:
  - `proof.signature_alg` → `proof.alg`
  - `proof.key_id` → `proof.kid`
  - `proof.signer` → `proof.signer_id`

### Added

- `PROTOCOL_VERSION` constant — export so every consumer can log which version it implements
- `CANONICAL_METHOD` constant — `"json.sorted_keys.v1"`, matches ENS `cl.sig.canonical` record
- `SIGNATURE_ALG` constant — `"ed25519"`
- `ENS_KEY_*` constants — canonical ENS text record key names
- `CANONICAL_TEST_VECTORS` — cross-repo canonical test vectors; import and run in your test suite
- `generateEd25519KeyPair()` — key generation utility for testing and provisioning
- `isSignedLayeredReceipt()` — type guard
- `verifyCanonicalWithRawKey()` — verify using raw 32-byte key from ENS directly
- npm `publishConfig` — package is now published to npm as `@commandlayer/runtime-core`
- Full CI via `.github/workflows/ci.yml`
- `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`
- `exports` map for subpath imports (`/canonicalize`, `/crypto`, `/ens`, `/receipt`)

### Changed

- `ethers` pinned to `^6.13.0` (was `^6.0.0`)
- ENS resolution (`ens.ts`) now hard-fails on resolution error — no silent fallback
- `signReceipt` validates required payload fields and throws descriptively
- `verifyReceipt` requires `signerMatched` to be true for `valid: true`

### Removed

- `dist/` from git tracking — add `dist/` to `.gitignore` and install from npm
- `src/shims.d.ts` — not needed on Node 20+

### Migration Guide

If you were installing via `github:commandlayer/runtime-core#main`:

```bash
# Remove the github: dep
npm uninstall @commandlayer/runtime-core

# Install from npm
npm install @commandlayer/runtime-core@1.1.0
```

If you were signing with sha256 hex (agent-sdk < 1.1.0, verifyagent < 1.1.0):
Update your signing code to sign raw canonical bytes. See `src/crypto.ts` for the
reference implementation.

---

## [1.0.0] — 2025-11-22

Initial release.
