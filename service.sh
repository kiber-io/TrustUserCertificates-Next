#!/system/bin/sh

if [ "${KSU:-}" = true ]; then
    BUSYBOX=/data/adb/ksu/bin/busybox
else
    BUSYBOX=/data/adb/magisk/busybox
fi
[ -x "$BUSYBOX" ] || { echo "Root manager BusyBox is unavailable" >&2; exit 1; }
if [ "${ASH_STANDALONE:-}" != 1 ]; then
    export ASH_STANDALONE=1
    exec "$BUSYBOX" sh "$0" "$@"
fi
set -e
[ "$(id -u)" = 0 ] || { echo "Root is required" >&2; exit 1; }

STATE=/data/adb/trustusercerts
mkdir -p "$STATE/certificates"
log() {
    echo "$(date '+%m-%d %H:%M:%S [trustusercerts]') $*" | tee -a "$STATE/module.log"
}

# KernelSU also calls service.sh after late-load; no blocking late-load.sh is needed.
while [ "$(getprop sys.boot_completed)" != 1 ]; do
    sleep 1
done

RUNTIME=/dev/trustusercerts
mkdir -p -m 700 "$RUNTIME"
mkdir "$RUNTIME/.lock" 2>/dev/null || { log "Another certificate update is running"; exit 1; }
STAGE=
STAGE_PUBLISHED=false
cleanup() {
    result=$?
    trap - EXIT
    if [ -n "$STAGE" ] && [ "$STAGE_PUBLISHED" = false ]; then
        rm -rf "$STAGE"
    fi
    rmdir "$RUNTIME/.lock"
    [ "$result" = 0 ] || log "Certificate update failed (exit $result)"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

SYSTEM_CERTS=/system/etc/security/cacerts
APEX_CERTS=/apex/com.android.conscrypt/cacerts
TARGETS="$SYSTEM_CERTS"
STOCK_SOURCE=$SYSTEM_CERTS
if [ -d "$APEX_CERTS" ]; then
    TARGETS="$TARGETS $APEX_CERTS"
    STOCK_SOURCE=$APEX_CERTS
fi

Z_PIDS=$(pidof zygote zygote64 || true)
[ -n "$Z_PIDS" ] || { log "No Zygote process found"; exit 1; }

# /dev is cleared on reboot: repeated actions must not keep removed user CAs.
STOCK=$RUNTIME/stock
mkdir -p -m 700 "$STOCK"
if [ ! -f "$STOCK/.ready" ]; then
    cp "$STOCK_SOURCE"/* "$STOCK/"
    touch "$STOCK/.ready"
fi

certificate_folder=/data/misc/user/0/cacerts-added
if [ -f "$STATE/no_user_cert" ]; then
    certificate_folder="$STATE/certificates"
fi

# /dev is already tmpfs and visible in existing namespaces; a new private mount isn't.
STAGE=$(mktemp -d "$RUNTIME/cacerts.XXXXXX")
cp "$STOCK"/* "$STAGE/"
for cert in "$certificate_folder"/*; do
    [ -f "$cert" ] || continue
    cp "$cert" "$STAGE/"
done
touch "$STAGE/.trustusercerts"
chown -R 0:0 "$STAGE"
chmod 755 "$STAGE"
chmod 644 "$STAGE"/*
chcon -R u:object_r:system_file:s0 "$STAGE"

# The source must resolve in the target namespace for mount --bind to accept it.
SOURCE=$STAGE
NS_BUSYBOX="/proc/$$/root$BUSYBOX"
inject_namespace() {
    for target in $TARGETS; do
        "$BUSYBOX" nsenter --mount="/proc/$1/ns/mnt" -- "$NS_BUSYBOX" sh -c '
            set -e
            # Remove only our previous bind mount, leaving other modules alone.
            if [ -f "$2/.trustusercerts" ]; then
                umount -l "$2"
            fi
            mount --bind "$1" "$2"
        ' sh "$SOURCE" "$target" || return 1
    done
}

STAGE_PUBLISHED=true
inject_namespace "$$"
for pid in $Z_PIDS; do
    inject_namespace "$pid"
done

# BusyBox ps has no -P option. Find the already running apps by their parent PID.
APP_PIDS=$(ps -o pid,ppid | awk -v parents=" $Z_PIDS " 'NR > 1 && index(parents, " " $2 " ") { print $1 }')
failed=false
for pid in $APP_PIDS; do
    if ! inject_namespace "$pid"; then
        if [ -d "/proc/$pid" ]; then
            log "Could not update certificates for process $pid"
            failed=true
        fi
    fi
done
[ "$failed" = false ] || exit 1

# shortcut: old CA snapshots stay in /dev until reboot; add namespace-aware cleanup if refreshes become frequent.
log "Certificates applied to Zygote and running apps (KSU_LATE_LOAD=${KSU_LATE_LOAD:-0})"
