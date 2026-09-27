#!/usr/bin/env bash
# Usage: newest-tag.sh <prefix> < tag-names
# Prints the newest <prefix>X.Y.Z or <prefix>X.Y.Z-rcN tag name. A release sorts
# after its own release candidates; dev, nightly, pre and -mesh tags are ignored.
# Exits 1 with no output when no tag matches.
set -euo pipefail
prefix=${1:?usage: newest-tag.sh <prefix>}
newest=$(awk -v p="$prefix" '
  index($0, p) == 1 {
    rest = substr($0, length(p) + 1)
    if (rest ~ /^[0-9]+\.[0-9]+\.[0-9]+$/) {
      split(rest, v, "."); printf "%d %d %d 1 0 %s\n", v[1], v[2], v[3], $0
    } else if (rest ~ /^[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+$/) {
      split(rest, a, "-rc"); split(a[1], v, "."); printf "%d %d %d 0 %d %s\n", v[1], v[2], v[3], a[2], $0
    }
  }' | sort -k1,1n -k2,2n -k3,3n -k4,4n -k5,5n | tail -n 1 | awk '{ print $6 }')
[ -n "$newest" ] || exit 1
echo "$newest"
