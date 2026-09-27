#!/usr/bin/env bash
# Tests report-issue.sh with a fake gh that logs its arguments.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
check() { if eval "$2"; then echo "ok - $1"; else echo "not ok - $1"; fail=1; fi; }
mkdir "$tmp/bin"
cat > "$tmp/bin/gh" <<'GH'
#!/usr/bin/env bash
echo "$*" >> "$FAKE_GH_LOG"
if [ "$1 $2" = "issue list" ] && [ -n "${FAKE_OPEN_ISSUE:-}" ]; then echo "$FAKE_OPEN_ISSUE"; fi
exit 0
GH
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" GITHUB_REPOSITORY=octocat/test RUN_URL=https://example.invalid/run/1
echo "report body" > "$tmp/body.md"
run() { # run <case> <open-issue> <status>
  export FAKE_GH_LOG="$tmp/$1.log" FAKE_OPEN_ISSUE=$2; : > "$FAKE_GH_LOG"
  rc=0; bash "$here/report-issue.sh" "$3" android-4.11.0 "$tmp/body.md" > "$tmp/$1.out" 2>&1 || rc=$?
}
run new '' conflict
check "conflict with no open issue creates one" 'grep -q "^issue create -R octocat/test --title Upstream drift: xmtp-mesh stack vs android-4.11.0 (conflict) --label upstream-drift" "$tmp/new.log"'
check "conflict with no open issue ensures the label" 'grep -q "^label create upstream-drift" "$tmp/new.log"'
check "conflict with no open issue edits nothing" '! grep -q "^issue edit" "$tmp/new.log"'
run upd 7 test-failure
check "failure with an open issue edits it" 'grep -q "^issue edit 7 " "$tmp/upd.log"'
check "failure with an open issue comments on it" 'grep -q "^issue comment 7 " "$tmp/upd.log"'
check "failure with an open issue opens no second issue" '! grep -q "^issue create" "$tmp/upd.log"'
run close 7 ok
check "ok with an open issue comments and closes it" 'grep -q "^issue comment 7 " "$tmp/close.log" && grep -q "^issue close 7 " "$tmp/close.log"'
run quiet '' ok
check "ok with no open issue only lists" '[ "$(wc -l < "$tmp/quiet.log")" -eq 1 ]'
run tmo 7 timeout
check "timeout makes no gh call" '[ ! -s "$tmp/tmo.log" ]'
check "timeout prints a warning" 'grep -q "::warning::" "$tmp/tmo.out"'
run bad '' nonsense
check "an unknown status exits 1" '[ "$rc" -eq 1 ]'
exit $fail
