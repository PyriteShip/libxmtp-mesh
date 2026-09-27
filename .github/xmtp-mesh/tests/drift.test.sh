#!/usr/bin/env bash
# Tests drift.sh against a throwaway repo: a clean replay, routine conflicts
# (Cargo.lock, or a file named in KEEP_UPSTREAM) that keep upstream's version, and a
# real conflict (reported, skipped, later commits still applied).
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
check() { if eval "$2"; then echo "ok - $1"; else echo "not ok - $1"; fail=1; fi; }

git init -q -b main "$tmp/r"; cd "$tmp/r"
git config user.name test; git config user.email test@example.com
printf 'up-1\n' > up.txt; printf 'lock-1\n' > Cargo.lock; printf 'version=1\n' > version.txt
git add .; git commit -qm base; git tag base
git switch -qc upstream
printf 'up-2\n' > up.txt; printf 'lock-2\n' > Cargo.lock; printf 'version=2\n' > version.txt
git commit -qam upstream; git tag newup
git switch -qc clean base; printf 'mesh\n' > mesh.txt; git add mesh.txt; git commit -qm 'feat: add mesh.txt'
git switch -qc stack clean
printf 'lock-1\nmesh-dep\n' > Cargo.lock; git commit -qam 'build: lock the mesh dep'
printf 'up-1 patched\n' > up.txt; git commit -qam 'fix: patch up.txt'
printf 'later\n' > later.txt; git add later.txt; git commit -qm 'feat: add later.txt'
git switch -qc pin clean
printf 'version=1-mesh\n' > version.txt; git commit -qam 'chore: pin the mesh version'
git switch -q main

rc=0; bash "$here/drift.sh" base clean newup "$tmp/clean.md" || rc=$?
check "clean replay exits 0" '[ "$rc" -eq 0 ]'
check "clean replay applies the stack file" '[ -f mesh.txt ]'
check "clean report says every commit applied" 'grep -q "Every commit applied" "$tmp/clean.md"'

rc=0; bash "$here/drift.sh" base stack newup "$tmp/stack.md" || rc=$?
check "a real conflict exits 2" '[ "$rc" -eq 2 ]'
check "the report names the conflicting file" 'grep -q "CONFLICT\*\* in \`up.txt\`" "$tmp/stack.md"'
check "the report names the conflicting commit" 'grep -q "fix: patch up.txt" "$tmp/stack.md"'
check "a Cargo.lock-only conflict keeps upstream Cargo.lock" '[ "$(cat Cargo.lock)" = lock-2 ]'
check "the report notes the kept Cargo.lock" 'grep -q "kept upstream \`Cargo.lock\`" "$tmp/stack.md"'
check "commits after a conflict still apply" '[ -f later.txt ]'
check "no cherry-pick is left in progress" '! git rev-parse -q --verify CHERRY_PICK_HEAD >/dev/null'
check "upstream's up.txt is untouched" '[ "$(cat up.txt)" = up-2 ]'

rc=0; bash "$here/drift.sh" base pin newup "$tmp/pin1.md" || rc=$?
check "a conflict in a file not in KEEP_UPSTREAM exits 2" '[ "$rc" -eq 2 ]'
rc=0; KEEP_UPSTREAM="Cargo.lock version.txt" bash "$here/drift.sh" base pin newup "$tmp/pin2.md" || rc=$?
check "a conflict only in KEEP_UPSTREAM files exits 0" '[ "$rc" -eq 0 ]'
check "KEEP_UPSTREAM keeps upstream's version" '[ "$(cat version.txt)" = version=2 ]'

rc=0; bash "$here/drift.sh" base nosuch newup "$tmp/x.md" 2>/dev/null || rc=$?
check "an unknown commit exits 1" '[ "$rc" -eq 1 ]'
exit $fail
