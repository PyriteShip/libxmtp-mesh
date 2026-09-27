#!/usr/bin/env bash
# Usage: report-issue.sh <ok|conflict|test-failure|timeout> <tag> <body-file>
# Keeps at most ONE open issue labelled upstream-drift in $GITHUB_REPOSITORY.
#   conflict, test-failure: update the open issue (title, body, a comment) or open one.
#   ok: comment on and close the open issue, if there is one.
#   timeout: touch nothing; print a warning (the cargo cache was saved; the next run is warm).
# Needs gh on PATH with GH_TOKEN, and GITHUB_REPOSITORY; RUN_URL is optional.
set -euo pipefail
[ $# -eq 3 ] || { echo "usage: report-issue.sh <status> <tag> <body-file>" >&2; exit 1; }
status=$1 tag=$2 body=$3
label=upstream-drift
repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}
run=${RUN_URL:-}
case $status in
  ok|conflict|test-failure) ;;
  timeout)
    echo "::warning::upstream-drift: the build hit its time limit on $tag. The cargo cache was saved, so the next run should finish. No issue was filed."
    exit 0 ;;
  *) echo "report-issue.sh: unknown status '$status'" >&2; exit 1 ;;
esac
open=$(gh issue list -R "$repo" --label "$label" --state open --json number --jq '.[0].number // empty')
if [ "$status" = ok ]; then
  if [ -n "$open" ]; then
    gh issue comment "$open" -R "$repo" --body "Resolved: the stack replays onto \`$tag\` and the tests pass. $run"
    gh issue close "$open" -R "$repo"
  fi
  exit 0
fi
title="Upstream drift: xmtp-mesh stack vs $tag ($status)"
if [ -n "$open" ]; then
  gh issue edit "$open" -R "$repo" --title "$title" --body-file "$body"
  gh issue comment "$open" -R "$repo" --body "Still failing ($status) on \`$tag\`. $run"
else
  gh label create "$label" -R "$repo" --color B60205 --description "The weekly upstream-drift check failed" --force
  gh issue create -R "$repo" --title "$title" --label "$label" --body-file "$body"
fi
