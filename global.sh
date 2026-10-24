#!/system/bin/sh
# Called by manage.sh while its update lock is held.
global_namespace() {
    global_pid=$1
    global_source=$2
    global_enabled=false
    [ ! -f "$global_source/system-enabled" ] || global_enabled=true
    # Enter once per process; both trust stores belong to the same namespace.
    "$BUSYBOX" nsenter --mount="/proc/$global_pid/ns/mnt" -- "/proc/$$/root$BUSYBOX" sh -c '
        set -e
        for store in system apex; do
            case "$store" in system) target=$2 ;; apex) target=$3 ;; esac
            [ -d "$1/$store" ] || continue
            # Individual stores are refreshed by restarting their configured apps.
            [ ! -f "$target/.trustusercerts-app" ] || continue
            if [ -f "$target/.trustusercerts-global" ]; then umount -l "$target"; fi
            if [ "$4" = true ]; then
                mount --bind "$1/$store" "$target"
                if ! mount -o remount,bind,ro "$target" "$target"; then
                    umount -l "$target"
                    exit 1
                fi
            fi
        done
    ' sh "$global_source" "$SYSTEM_CERTS" "$APEX_CERTS" "$global_enabled" || return 1
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
