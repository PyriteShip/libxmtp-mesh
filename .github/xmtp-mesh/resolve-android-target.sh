#!/usr/bin/env bash
# Usage: resolve-android-target.sh <prefix> <base-tag> < android/build.gradle
#
# The libxmtp drift target isn't the newest libxmtp android-* tag. It's resolved
# from the org.xmtp:android version that the newest xmtp-react-native release actually
# pins in its android/build.gradle (the RN fork can't consume a newer libxmtp AAR
# until upstream RN moves to it). Reads that file's content on stdin.
#
# Prints:
#   tag=<prefix><pin>
#   skip=true|false     (true when <prefix><pin> equals <base-tag>: no drift)
# Exits 1 with no output if no org.xmtp:android pin is found.
set -euo pipefail
prefix=${1:?usage: resolve-android-target.sh <prefix> <base-tag>}
base=${2:?usage: resolve-android-target.sh <prefix> <base-tag>}
pin=$(grep -oE "org\.xmtp:android:[^\"'[:space:]]*" | head -n 1 | sed 's/^org\.xmtp:android://')
[ -n "$pin" ] || { echo "resolve-android-target.sh: no org.xmtp:android pin found" >&2; exit 1; }
tag="$prefix$pin"
skip=false
[ "$tag" = "$base" ] && skip=true
echo "tag=$tag"
echo "skip=$skip"
