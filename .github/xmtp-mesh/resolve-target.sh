#!/usr/bin/env bash
# Usage: resolve-target.sh <prefix> <base-tag> <rn-tag> < android/build.gradle-or-empty
#
# Wraps resolve-android-target.sh so a failed resolution — a moved or renamed
# android/build.gradle, an unparseable org.xmtp:android pin, or empty input from
# an upstream fetch that itself failed — never aborts the caller under `set -e`.
# Always exits 0. Prints, on success:
#   resolved=true
#   tag=<prefix><pin>
#   skip=true|false
# or, when resolve-android-target.sh can't extract a pin from stdin:
#   resolved=false
#   reason=<one-line message>
set -euo pipefail
prefix=${1:?usage: resolve-target.sh <prefix> <base-tag> <rn-tag>}
base=${2:?usage: resolve-target.sh <prefix> <base-tag> <rn-tag>}
rn_tag=${3:?usage: resolve-target.sh <prefix> <base-tag> <rn-tag>}
here=$(cd "$(dirname "$0")" && pwd)
gradle=$(cat)
if plan=$(printf '%s' "$gradle" | "$here/resolve-android-target.sh" "$prefix" "$base" 2>/dev/null); then
  echo "resolved=true"
  printf '%s\n' "$plan"
else
  echo "resolved=false"
  echo "reason=couldn't find an org.xmtp:android pin in xmtp-react-native's android/build.gradle at $rn_tag"
fi
