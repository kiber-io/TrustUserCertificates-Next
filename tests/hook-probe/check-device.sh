#!/usr/bin/env bash
set -euo pipefail
serial=${1:?Usage: check-device.sh SERIAL EXPECTED_FLAGS [ANDROID_USER_ID]}
flags=${2:?Expected flags: CT=1, User=2, System=4; sum 0..7}
user=${3:-0}
[[ "$flags" =~ ^[0-7]$ && "$user" =~ ^(0|[1-9][0-9]*)$ ]] || { echo 'Invalid flags or Android user ID' >&2; exit 2; }
adb_cmd=(adb -s "$serial")
package=io.kiber.tuc.probe
report=/data/user/$user/$package/files/report.txt
"${adb_cmd[@]}" shell "am force-stop --user $user $package"
"${adb_cmd[@]}" shell "su -c 'rm -f $report'"
"${adb_cmd[@]}" shell "am start --user $user -n $package/.ProbeActivity" >/dev/null
result=''
for attempt in {1..30}; do
    result=$("${adb_cmd[@]}" shell "su -c 'cat $report'" 2>/dev/null || true)
    [[ -z "$result" ]] || break
    sleep 0.2
done
sdk=$("${adb_cmd[@]}" shell getprop ro.build.version.sdk)
python3 - "$flags" "${sdk//$'\r'/}" "$result" <<'PY'
import re, sys
flags, sdk = map(int, sys.argv[1:3])
report = sys.argv[3].replace('\r', '')
print(report)
expected_ct = 'UNSUPPORTED' if sdk < 36 else 'DISABLED' if flags & 1 else 'REQUIRED'
assert f'CT: {expected_ct}\n' in report, 'Unexpected CT policy'
for name, bit in [('User', 2), ('System', 4)]:
    if flags & bit:
        assert re.search(rf'^{name} CAs: ENABLED \([0-9]+ CAs\)$', report, re.M), f'{name} source missing'
    else:
        assert f'{name} CAs: ABSENT\n' in report, f'Unexpected {name} source'
assert 'Embedded CAs: ENABLED (1 CAs)' in report, 'Embedded CA must survive every combination'
print(f'PASS: real application config, flags={flags}')
PY
