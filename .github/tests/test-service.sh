#!/system/bin/sh
# Run as root on Android: busybox sh test-service.sh /path/to/service.sh
set -e
BUSYBOX=/data/adb/ksu/bin/busybox
export ASH_STANDALONE=1 KSU=true KSU_LATE_LOAD=1
if [ "${TUC_TEST_PRIVATE:-}" != 1 ]; then
    export TUC_TEST_PRIVATE=1
    exec "$BUSYBOX" unshare -m --propagation private "$BUSYBOX" sh "$0" "$@"
fi

SERVICE=${1:-${0%/*}/../../service.sh}
ROOT=$(mktemp -d /data/local/tmp/trustusercerts-test.XXXXXX)
APP_PID=
cleanup_test() {
    [ -z "$APP_PID" ] || kill "$APP_PID" 2>/dev/null || true
    awk -v root="$ROOT/" 'index($5, root) == 1 { print $5 }' /proc/self/mountinfo |
        while read -r path; do umount -l "$path"; done
    rm -rf "$ROOT"
}
trap cleanup_test EXIT
trap 'exit 1' HUP INT TERM

# Override discovery only; use real bind mounts, nsenter and SELinux labels.
getprop() { echo 1; }
pidof() { echo "$$"; }
ps() { printf 'PID PPID\n%s %s\n' "$APP_PID" "$$"; }

apply() { ( . "$ROOT/service.sh" ); }
assert_cert() {
    [ "$(cat "$ROOT/system/$1")" = "$2" ]
    "$BUSYBOX" nsenter --mount="/proc/$APP_PID/ns/mnt" -- "$BUSYBOX" sh -c \
        '[ "$(cat "$1")" = "$2" ]' sh "$ROOT/system/$1" "$2"
    if [ -d "$ROOT/apex" ]; then
        [ "$(cat "$ROOT/apex/$1")" = "$2" ]
        "$BUSYBOX" nsenter --mount="/proc/$APP_PID/ns/mnt" -- "$BUSYBOX" sh -c \
            '[ "$(cat "$1")" = "$2" ]' sh "$ROOT/apex/$1" "$2"
    fi
}
assert_removed() {
    [ ! -e "$ROOT/system/$1" ]
    "$BUSYBOX" nsenter --mount="/proc/$APP_PID/ns/mnt" -- "$BUSYBOX" sh -c \
        '[ ! -e "$1" ]' sh "$ROOT/system/$1"
}

for mode in apex system; do
    mkdir -p "$ROOT/system" "$ROOT/user" "$ROOT/state/certificates"
    echo stock > "$ROOT/system/aaaaaaaa.0"
    if [ "$mode" = apex ]; then
        mkdir "$ROOT/apex"
        echo stock > "$ROOT/apex/aaaaaaaa.0"
        echo apex-only > "$ROOT/apex/cccccccc.0"
    fi
    sed -e "s|/data/adb/trustusercerts|$ROOT/state|g" \
        -e "s|/dev/trustusercerts|$ROOT/runtime|g" \
        -e "s|/system/etc/security/cacerts|$ROOT/system|g" \
        -e "s|/apex/com.android.conscrypt/cacerts|$ROOT/apex|g" \
        -e "s|/data/misc/user/0/cacerts-added|$ROOT/user|g" \
        "$SERVICE" > "$ROOT/service.sh"

    "$BUSYBOX" unshare -m --propagation private "$BUSYBOX" sleep 300 &
    APP_PID=$!
    for attempt in 1 2 3 4 5; do
        [ "$(readlink /proc/$APP_PID/ns/mnt)" != "$(readlink /proc/$$/ns/mnt)" ] && break
        sleep 1
    done
    [ "$(readlink /proc/$APP_PID/ns/mnt)" != "$(readlink /proc/$$/ns/mnt)" ]

    echo user > "$ROOT/user/bbbbbbbb.0"
    apply
    assert_cert aaaaaaaa.0 stock
    assert_cert bbbbbbbb.0 user
    [ "$(stat -c %a "$ROOT/system")" = 755 ]
    [ "$(stat -c %a "$ROOT/system/bbbbbbbb.0")" = 644 ]
    if [ "$mode" = apex ]; then assert_cert cccccccc.0 apex-only; fi

    rm "$ROOT/user/bbbbbbbb.0"
    apply
    assert_cert aaaaaaaa.0 stock
    assert_removed bbbbbbbb.0

    touch "$ROOT/state/no_user_cert"
    echo custom > "$ROOT/state/certificates/dddddddd.0"
    echo ignored > "$ROOT/user/eeeeeeee.0"
    apply
    assert_cert dddddddd.0 custom
    assert_removed eeeeeeee.0

    # A failed setup must leave the existing trust store and release its lock.
    snapshots=$(find "$ROOT/runtime" -maxdepth 1 -name 'cacerts.*' | wc -l)
    set +e
    ( chcon() { return 1; }; . "$ROOT/service.sh" )
    result=$?
    set -e
    [ "$result" != 0 ]
    assert_cert aaaaaaaa.0 stock
    assert_cert dddddddd.0 custom
    [ ! -d "$ROOT/runtime/.lock" ]
    set +e
    ( cp() { return 1; }; . "$ROOT/service.sh" )
    result=$?
    set -e
    [ "$result" != 0 ]
    assert_cert dddddddd.0 custom
    [ ! -d "$ROOT/runtime/.lock" ]
    [ "$(find "$ROOT/runtime" -maxdepth 1 -name 'cacerts.*' | wc -l)" = "$snapshots" ]

    # Repeated actions must leave one module mount per target, not a growing stack.
    [ "$(awk -v target="$ROOT/system" '$5 == target { count++ } END { print count+0 }' /proc/self/mountinfo)" = 1 ]
    kill "$APP_PID"
    wait "$APP_PID" 2>/dev/null || true
    APP_PID=
    cleanup_test
    mkdir "$ROOT"
    echo "PASS: $mode certificates, removal, custom folder, namespaces, setup failures"
done
