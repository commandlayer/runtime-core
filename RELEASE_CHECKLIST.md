# Release Checklist — @commandlayer/runtime-core

This checklist is for preparing npm releases of `@commandlayer/runtime-core`.

## Package metadata

- [ ] `package.json` name is `@commandlayer/runtime-core`
- [ ] `package.json` version matches intended semver bump
- [ ] `main`, `types`, and `exports` point to `dist/` outputs
- [ ] `files` includes `dist/`, `README.md`, `LICENSE`, `CHANGELOG.md`

## Protocol and API compatibility

- [ ] CLAS canonicalization remains `json.sorted_keys.v1`
- [ ] Hash algorithm remains `SHA-256`
- [ ] Signature algorithm remains `Ed25519` (legacy lowercase only for compatibility in verification)
- [ ] Verification remains fail-closed for malformed/invalid proofs
- [ ] Any public API change is documented in `CHANGELOG.md`

## Documentation

- [ ] README install instructions use npm registry package (`npm install @commandlayer/runtime-core@<version>`)
- [ ] README proof envelope docs match current implementation
- [ ] CHANGELOG contains release entry with migration notes when needed

## Local release-readiness checks

Run and verify all pass:

- [ ] `npm install`
- [ ] `npm run build`
- [ ] `npm test`
- [ ] `npm run typecheck`
- [ ] `npm pack --dry-run`

## Package content review

- [ ] Tarball includes only intended publish artifacts
- [ ] Tarball excludes secrets, local env files, and irrelevant test/dev junk
- [ ] Dist output contains JS and `.d.ts` for exported entry points

## Finalization

- [ ] Commit release-readiness updates
- [ ] Open PR with checks/results and any publish blockers
- [ ] Do **not** publish from this checklist workflow
