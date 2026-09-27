#!/usr/bin/env bash
# Tests check-patches.sh against a throwaway repo.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
check() { if eval "$2"; then echo "ok - $1"; else echo "not ok - $1"; fail=1; fi; }
git init -q -b main "$tmp/r"; cd "$tmp/r"
git config user.name test; git config user.email test@example.com
printf 'a\n' > up.txt; printf 'b\n' > gone.txt; git add .; git commit -qm base
base=$(git rev-parse HEAD)
printf 'a2\n' > up.txt; git rm -q gone.txt; printf 'n\n' > new.txt; git add .; git commit -qm stack
printf 'Base commit: %s\n\n| `up.txt` | x |\n| `gone.txt` | x |\n' "$base" > good.md
printf 'Base commit: %s\n\n| `gone.txt` | x |\n' "$base" > stale.md
printf 'no base line\n' > nobase.md
rc=0; bash "$here/check-patches.sh" good.md > out.txt || rc=$?
check "a complete PATCHES.md passes" '[ "$rc" -eq 0 ]'
rc=0; bash "$here/check-patches.sh" stale.md > out.txt || rc=$?
check "a missing modified file fails" '[ "$rc" -eq 1 ]'
check "the failure names the file" 'grep -q "file: up.txt" out.txt'
check "new files need not be listed" '! grep -q new.txt out.txt'
rc=0; bash "$here/check-patches.sh" nobase.md > out.txt 2>&1 || rc=$?
check "no Base commit line fails" '[ "$rc" -eq 1 ] && grep -q "Base commit" out.txt'
exit $fail
