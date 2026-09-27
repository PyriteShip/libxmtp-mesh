#!/usr/bin/env bash
# Usage: check-patches.sh <PATCHES.md> [<head>]
# Fails, naming each file, if an upstream file that <head> (default HEAD) modifies or
# deletes relative to PATCHES.md's "Base commit:" is not written in PATCHES.md as `path`.
# New files need not be listed one by one.
set -euo pipefail
doc=${1:?usage: check-patches.sh <PATCHES.md> [<head>]}
head=${2:-HEAD}
base=$(sed -n 's/^Base commit: \([0-9a-f]\{40\}\)$/\1/p' "$doc")
[ -n "$base" ] || { echo "check-patches.sh: $doc has no 'Base commit: <40 hex>' line" >&2; exit 1; }
missing=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if ! grep -qF "\`$f\`" "$doc"; then
    echo "PATCHES.md does not list this edited upstream file: $f"
    missing=1
  fi
done < <(git diff --no-renames --name-only --diff-filter=MDT "$base" "$head")
[ "$missing" -eq 0 ] && echo "ok - PATCHES.md lists every edited upstream file"
exit "$missing"
