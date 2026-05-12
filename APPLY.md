# runtime-core — Apply Instructions
# Apply in this exact order

# ── Step 1: Deletions ────────────────────────────────────────────────────────
bash DELETIONS.sh

# ── Step 2: Replace source files ────────────────────────────────────────────
# Copy these files into the repo (replacing existing):
#   src/crypto.ts       ← new: protocol constants, standard base64, raw-byte signing
#   src/ens.ts          ← new: hard-fail ENS, standard base64 key parsing
#   src/canonicalize.ts ← new: single implementation + CANONICAL_TEST_VECTORS
#   src/receipt.ts      ← new: correct proof field names (alg/kid/signer_id)
#   src/index.ts        ← new: clean public API export

# ── Step 3: New files ────────────────────────────────────────────────────────
#   test/canonicalize.test.ts
#   test/crypto.test.ts
#   test/receipt.test.ts
#   .github/workflows/ci.yml
#   .gitignore             (replaces or creates)
#   .env.example
#   CHANGELOG.md
#   SECURITY.md
#   CONTRIBUTING.md
#   package.json           (replace: pins ethers ^6.13.0, adds publishConfig, exports map)

# ── Step 4: Install & verify ─────────────────────────────────────────────────
npm install
npm run build
npm test

# Expected output: all tests pass, no type errors

# ── Step 5: Commit ───────────────────────────────────────────────────────────
git add -A
git commit -m "feat: v1.1.0 protocol alignment

- Fix signing message: raw canonical UTF-8 bytes (not sha256 hex)
- Fix ENS key encoding: standard base64 with = padding
- Fix proof field names: alg/kid/signer_id (not signature_alg/key_id/signer)
- Remove dist/ from git, add to .gitignore
- Add publishConfig for npm publication
- Add CI workflow
- Add CANONICAL_TEST_VECTORS for cross-repo alignment
- Add CHANGELOG.md, SECURITY.md, CONTRIBUTING.md
- ENS resolution now hard-fails (no silent fallback)"

git tag v1.1.0
git push origin main --follow-tags

# ── Step 6: Publish to npm ───────────────────────────────────────────────────
npm publish
# After this, all other repos switch from github:commandlayer/runtime-core#main
# to @commandlayer/runtime-core@1.1.0
