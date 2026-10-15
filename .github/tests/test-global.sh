#!/system/bin/sh
# Run on Android as root; only temporary directories in private namespaces are mounted.
set -eu
BUSYBOX=/data/adb/ksu/bin/busybox
export ASH_STANDALONE=1
if [ "${TUC_GLOBAL_PRIVATE:-}" != 1 ]; then
    export TUC_GLOBAL_PRIVATE=1
    exec "$BUSYBOX" unshare -m --propagation private "$BUSYBOX" sh "$0" "$@"
fi
ROOT=$(mktemp -d /data/local/tmp/trustusercerts-global-test.XXXXXX)
APP_PID=
cleanup() {
    [ -z "$APP_PID" ] || kill "$APP_PID" 2>/dev/null || true
    awk -v root="$ROOT/" 'index($5, root) == 1 {print $5}' /proc/self/mountinfo |
        while IFS= read -r path; do umount -l "$path"; done
    rm -rf "$ROOT"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
. "$1"
SYSTEM_CERTS=$ROOT/system
APEX_CERTS=$ROOT/apex
mkdir "$SYSTEM_CERTS" "$APEX_CERTS"
echo stock > "$SYSTEM_CERTS/aaaaaaaa.0"
echo stock > "$APEX_CERTS/aaaaaaaa.0"
for generation in on off changed user-only; do
    mkdir -p "$ROOT/$generation/system" "$ROOT/$generation/apex"
    for store in system apex; do
        cp "$ROOT/$store/aaaaaaaa.0" "$ROOT/$generation/$store/"
        touch "$ROOT/$generation/$store/.trustusercerts-global"
    done
done
touch "$ROOT/on/enabled" "$ROOT/changed/enabled" "$ROOT/user-only/enabled" "$ROOT/on/system-enabled" "$ROOT/changed/system-enabled"
echo custom > "$ROOT/on/system/bbbbbbbb.0"
echo custom > "$ROOT/on/apex/bbbbbbbb.0"
echo other > "$ROOT/changed/system/cccccccc.0"
echo other > "$ROOT/changed/apex/cccccccc.0"
echo never-system > "$ROOT/user-only/system/dddddddd.0"
"$BUSYBOX" unshare -m --propagation private "$BUSYBOX" sleep 120 &
APP_PID=$!
for attempt in 1 2 3 4 5; do
    [ "$(readlink /proc/$APP_PID/ns/mnt)" != "$(readlink /proc/$$/ns/mnt)" ] && break
    sleep 1
done
[ "$(readlink /proc/$APP_PID/ns/mnt)" != "$(readlink /proc/$$/ns/mnt)" ]
global_namespace "$APP_PID" "$ROOT/on"
[ -f "/proc/$APP_PID/root$SYSTEM_CERTS/bbbbbbbb.0" ]
[ ! -f "$SYSTEM_CERTS/bbbbbbbb.0" ]
global_namespace "$APP_PID" "$ROOT/changed"
[ ! -f "/proc/$APP_PID/root$SYSTEM_CERTS/bbbbbbbb.0" ]
[ -f "/proc/$APP_PID/root$APEX_CERTS/cccccccc.0" ]
global_namespace "$APP_PID" "$ROOT/user-only"
[ ! -f "/proc/$APP_PID/root$SYSTEM_CERTS/cccccccc.0" ]
[ ! -f "/proc/$APP_PID/root$SYSTEM_CERTS/dddddddd.0" ]
[ -f "/proc/$APP_PID/root$SYSTEM_CERTS/aaaaaaaa.0" ]
global_namespace "$$" "$ROOT/on"
global_namespace "$$" "$ROOT/changed"
[ ! -f "$SYSTEM_CERTS/bbbbbbbb.0" ]
[ -f "$SYSTEM_CERTS/cccccccc.0" ]
if (echo fail > "$SYSTEM_CERTS/readonly-test") 2>/dev/null; then exit 1; fi
global_namespace "$$" "$ROOT/off"
[ ! -f "$SYSTEM_CERTS/cccccccc.0" ]
[ -f "$SYSTEM_CERTS/aaaaaaaa.0" ]
# A per-app overlay must not be overwritten by a global-only refresh.
touch "$ROOT/on/system/.trustusercerts-app"
mount --bind "$ROOT/on/system" "$SYSTEM_CERTS"
global_namespace "$$" "$ROOT/changed"
[ -f "$SYSTEM_CERTS/bbbbbbbb.0" ]
echo 'PASS: private global mounts, replacement, removal, read-only and per-app protection'
