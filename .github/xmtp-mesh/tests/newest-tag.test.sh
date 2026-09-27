#!/usr/bin/env bash
# Tests newest-tag.sh.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
fail=0
eq() { if [ "$2" = "$3" ]; then echo "ok - $1"; else echo "not ok - $1: got '$2', want '$3'"; fail=1; fi; }
pick() { local p=$1; shift; printf '%s\n' "$@" | bash "$here/newest-tag.sh" "$p" || true; }
eq "a release beats its rc; dev, nightly, pre and mesh tags are ignored" \
  "$(pick android- android-4.10.0-rc2 android-4.10.0 android-4.11.0-rc1 android-4.11.0 android-4.12.0-dev.e7edced android-4.12.0-nightly.20260805.d14feba android-4.12.0-pre.20260828090205.nightly.cc87802 android-4.10.0-rc2-mesh.7)" \
  android-4.11.0
eq "a newer rc beats an older release" "$(pick android- android-4.11.0 android-4.12.0-rc1)" android-4.12.0-rc1
eq "versions compare numerically" "$(pick android- android-4.9.0 android-4.10.0)" android-4.10.0
eq "rc numbers compare numerically" "$(pick android- android-4.12.0-rc9 android-4.12.0-rc10)" android-4.12.0-rc10
eq "other prefixes are ignored" "$(pick android- kotlin-bindings-9.9.9 ios-9.9.9 android-4.10.0)" android-4.10.0
eq "the v prefix works for the RN SDK" "$(pick v v5.7.0 v5.10.0 v5.3.0-dev.21b09ae v5.1.0-rc1.cfbcd1a)" v5.10.0
rc=0; printf 'nothing\n' | bash "$here/newest-tag.sh" android- > /dev/null || rc=$?
eq "no match exits 1" "$rc" 1
exit $fail
