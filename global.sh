#!/system/bin/sh
# Called by manage.sh while its update lock is held.
global_namespace() {
    global_pid=$1
    global_source=$2
    global_enabled=false
    [ ! -f "$global_source/system-enabled" ] || global_enabled=true
    for global_store in system apex; do
        case "$global_store" in system) global_target=$SYSTEM_CERTS ;; apex) global_target=$APEX_CERTS ;; esac
        [ -d "$global_source/$global_store" ] || continue
        "$BUSYBOX" nsenter --mount="/proc/$global_pid/ns/mnt" -- "/proc/$$/root$BUSYBOX" sh -c '
            set -e
            # Individual stores are refreshed by restarting their configured apps.
            [ ! -f "$2/.trustusercerts-app" ] || exit 0
            if [ -f "$2/.trustusercerts-global" ]; then umount -l "$2"; fi
            if [ "$3" = true ]; then
                mount --bind "$1" "$2"
                if ! mount -o remount,bind,ro "$2" "$2"; then
                    umount -l "$2"
                    exit 1
                fi
            fi
        ' sh "$global_source/$global_store" "$global_target" "$global_enabled" || return 1
    done
}

apply_global() {
    global_snapshot=$1
    global_failed=false
    global_zygotes=$(pidof zygote zygote64 || true)
    [ -n "$global_zygotes" ] || return 1
    global_namespace "$$" "$global_snapshot" || return 1
    for global_pid in $global_zygotes; do
        global_namespace "$global_pid" "$global_snapshot" || return 1
    done
    global_apps=$(ps -o pid,ppid | awk -v parents=" $global_zygotes " 'NR > 1 && index(parents, " " $2 " ") {print $1}')
    for global_pid in $global_apps; do
        if ! global_namespace "$global_pid" "$global_snapshot"; then
            if [ -d "/proc/$global_pid" ]; then
                log "Could not update global certificates in process $global_pid"
                global_failed=true
            fi
        fi
    done
    [ "$global_failed" = false ]
}
