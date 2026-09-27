#!/usr/bin/env bash
# Usage: [KEEP_UPSTREAM="Cargo.lock ..."] drift.sh <base> <stack-tip> <onto> <report.md>
# Replays every commit in <base>..<stack-tip> onto <onto> (detached HEAD, current repo)
# and writes a Markdown table of the results to <report.md>.
# KEEP_UPSTREAM (default "Cargo.lock") lists files whose conflicts are routine: when
# every conflicted file of a commit is in the list, upstream's version is kept and the
# commit counts as applied (cargo re-resolves Cargo.lock on the next build).
# Exit 0: every commit applied.
# Exit 2: at least one commit conflicted; each is listed and skipped, later ones still run.
# Exit 1: bad arguments or a git error.
set -euo pipefail
[ $# -eq 4 ] || { echo "usage: drift.sh <base> <stack-tip> <onto> <report.md>" >&2; exit 1; }
base=$1 tip=$2 onto=$3 report=$4
keep=" ${KEEP_UPSTREAM-Cargo.lock} "
for r in "$base" "$tip" "$onto"; do
  git rev-parse -q --verify "$r^{commit}" >/dev/null || { echo "drift.sh: unknown commit $r" >&2; exit 1; }
done
git -c advice.detachedHead=false checkout -q --detach "$onto"
{
  echo "## Replay of the xmtp-mesh stack onto \`$onto\`"
  echo
  echo "- base: \`$(git rev-parse "$base^{commit}")\`"
  echo "- stack tip: \`$(git rev-parse "$tip^{commit}")\`"
  echo "- onto: \`$(git rev-parse "$onto^{commit}")\`"
  echo
  echo "| commit | subject | result |"
  echo "|---|---|---|"
} > "$report"
conflicts=0
for c in $(git rev-list --reverse "$base..$tip"); do
  short=$(git rev-parse --short=10 "$c")
  subj=$(git log -1 --format=%s "$c" | sed 's/|/\\|/g')
  if git cherry-pick --keep-redundant-commits -x "$c" >/dev/null 2>&1; then
    echo "| $short | $subj | applied |" >> "$report"
    continue
  fi
  unmerged=$(git diff --name-only --diff-filter=U)
  routine=yes
  [ -n "$unmerged" ] || routine=no
  for f in $unmerged; do
    case "$keep" in *" $f "*) ;; *) routine=no ;; esac
  done
  if [ "$routine" = yes ]; then
    for f in $unmerged; do git checkout -q --ours -- "$f"; git add -- "$f"; done
    git commit -q --allow-empty --no-edit
    kept=$(printf '%s\n' $unmerged | sed 's/.*/`&`/' | paste -sd ' ' -)
    echo "| $short | $subj | applied (kept upstream $kept) |" >> "$report"
    continue
  fi
  files=$(printf '%s\n' "$unmerged" | sed '/^$/d; s/.*/`&`/' | paste -sd ' ' -)
  git cherry-pick --abort 2>/dev/null || git reset -q --hard
  conflicts=$((conflicts + 1))
  echo "| $short | $subj | **CONFLICT** in ${files:-(no unmerged path; the pick failed for another reason)}; skipped |" >> "$report"
done
echo >> "$report"
if [ "$conflicts" -gt 0 ]; then
  echo "**$conflicts commit(s) conflicted.** Later commits were still tried on top of the skipped ones." >> "$report"
  exit 2
fi
echo "Every commit applied." >> "$report"
