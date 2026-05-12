# DELETIONS — runtime-core
# Run these commands in the repo root before applying the new files

# 1. Remove dist/ from git tracking entirely
git rm -r --cached dist/
# (The new .gitignore will prevent it from being re-added)

# 2. Remove shims if present (not needed on Node 20+)
git rm -f src/shims.d.ts 2>/dev/null || true

# 3. Confirm .gitignore now has dist/ entry (added in new .gitignore file)
grep "dist/" .gitignore && echo "✓ dist/ is gitignored"

# 4. Stage the deletions
git add .gitignore
git add -A

echo "Deletion step complete. Apply new files next, then: npm install && npm run build && npm test"
