#!/usr/bin/env bash
# Tests resolve-target.sh: it never aborts, even when resolve-android-target.sh
# can't parse its input (a moved file, a renamed dependency, a failed upstream
# fetch).
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
fail=0
check() { if eval "$2"; then echo "ok - $1"; else echo "not ok - $1"; fail=1; fi; }

rc=0
out=$(printf '%s\n' '  implementation "org.xmtp:android:4.10.0-rc2"' \
  | bash "$here/resolve-target.sh" android- android-4.10.0-rc2 v5.7.0) || rc=$?
check "a parseable pin exits 0" '[ "$rc" -eq 0 ]'
check "a parseable pin resolves" 'grep -q "^resolved=true$" <<< "$out"'
check "a parseable pin passes the tag through" 'grep -q "^tag=android-4.10.0-rc2$" <<< "$out"'
check "a parseable pin passes skip through" 'grep -q "^skip=true$" <<< "$out"'

rc=0
out=$(printf 'no pin in here\n' | bash "$here/resolve-target.sh" android- android-4.10.0-rc2 v5.7.0) || rc=$?
check "unparseable input does not abort" '[ "$rc" -eq 0 ]'
check "unparseable input is unresolved, not a crash" 'grep -q "^resolved=false$" <<< "$out"'
check "unparseable input gives a reason naming the rn tag" 'grep -q "^reason=.*v5.7.0" <<< "$out"'
check "unparseable input prints no tag= line" '! grep -q "^tag=" <<< "$out"'
check "unparseable input prints no skip= line" '! grep -q "^skip=" <<< "$out"'

rc=0
out=$(printf '' | bash "$here/resolve-target.sh" android- android-4.10.0-rc2 unknown) || rc=$?
check "empty input (e.g. a failed git show) does not abort" '[ "$rc" -eq 0 ]'
check "empty input is unresolved" 'grep -q "^resolved=false$" <<< "$out"'

rc=0
bash "$here/resolve-target.sh" android- android-4.10.0-rc2 > /dev/null 2>&1 </dev/null || rc=$?
check "a missing rn-tag argument is a usage error, not an unresolved outcome" '[ "$rc" -ne 0 ]'
exit $fail
