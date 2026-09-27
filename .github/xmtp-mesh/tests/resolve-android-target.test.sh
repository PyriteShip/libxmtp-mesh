#!/usr/bin/env bash
# Tests resolve-android-target.sh (the libxmtp drift target is resolved from
# the newest xmtp-react-native release's android/build.gradle org.xmtp:android pin,
# not from libxmtp's own android-* tags).
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
fail=0
check() { if eval "$2"; then echo "ok - $1"; else echo "not ok - $1"; fail=1; fi; }

out=$(printf '%s\n' '  implementation "org.xmtp:android:4.10.0-rc2"' \
  | bash "$here/resolve-android-target.sh" android- android-4.10.0-rc2)
check "a pin equal to the base tag resolves that tag" 'grep -q "^tag=android-4.10.0-rc2$" <<< "$out"'
check "a pin equal to the base tag sets skip=true" 'grep -q "^skip=true$" <<< "$out"'

out=$(printf '%s\n' '  implementation "org.xmtp:android:4.11.0"' \
  | bash "$here/resolve-android-target.sh" android- android-4.10.0-rc2)
check "a newer pin resolves the newer tag" 'grep -q "^tag=android-4.11.0$" <<< "$out"'
check "a newer pin sets skip=false" 'grep -q "^skip=false$" <<< "$out"'

out=$(printf '%s\n' "  implementation 'org.xmtp:android:4.11.0-rc1'" \
  | bash "$here/resolve-android-target.sh" android- android-4.10.0-rc2)
check "single-quoted Gradle syntax also parses" 'grep -q "^tag=android-4.11.0-rc1$" <<< "$out"'

out=$(printf '%s\n' '  api "org.xmtp:proto-kotlin:3.88.0"' 'implementation "org.xmtp:android:4.11.0"' \
  | bash "$here/resolve-android-target.sh" android- android-4.10.0-rc2)
check "an unrelated org.xmtp dependency on an earlier line is not matched" 'grep -q "^tag=android-4.11.0$" <<< "$out"'

rc=0; printf 'no pin in here\n' | bash "$here/resolve-android-target.sh" android- android-4.10.0-rc2 > /dev/null 2>&1 || rc=$?
check "no pin found exits 1" '[ "$rc" -eq 1 ]'
exit $fail
