#!/system/bin/sh
set -eu
MODDIR=${0%/*}
if [ "${KSU:-}" = true ] || [ -x /data/adb/ksu/bin/busybox ]; then
    BUSYBOX=/data/adb/ksu/bin/busybox
else
    BUSYBOX=/data/adb/magisk/busybox
fi
[ -x "$BUSYBOX" ] || { echo 'Root manager BusyBox is unavailable' >&2; exit 1; }
if [ "${ASH_STANDALONE:-}" != 1 ]; then
    export ASH_STANDALONE=1
    exec "$BUSYBOX" sh "$0" "$@"
fi
set -o pipefail
[ "$(id -u)" = 0 ] || { echo 'Root is required' >&2; exit 1; }
umask 077
STATE=/data/adb/trustusercerts
RUNTIME=/dev/trustusercerts
SYSTEM_CERTS=/system/etc/security/cacerts
APEX_CERTS=/apex/com.android.conscrypt/cacerts
mkdir -p "$STATE/empty/certificates" "$RUNTIME"
chmod 700 "$STATE" "$STATE/empty" "$STATE/empty/certificates" "$RUNTIME"
touch "$STATE/empty/rules"
SETTINGS=$STATE/empty
if [ -L "$STATE/settings" ]; then SETTINGS=$(readlink -f "$STATE/settings"); fi
cert_tool() { CLASSPATH="$MODDIR/cert-tool.jar" /system/bin/app_process / CertTool "$@"; }
app_tool() { CLASSPATH="$MODDIR/cert-tool.jar" /system/bin/app_process / AppTool "$@"; }
log() { echo "$(date '+%m-%d %H:%M:%S [trustusercerts]') $*" >> "$STATE/module.log"; }
fail() { log "$*"; echo "$*" >&2; exit 1; }
app_map() {
    users=$(/system/bin/pm list users | sed -n 's/^[[:space:]]*UserInfo{\([^:}]*\):.*/\1/p')
    [ -n "$users" ] || fail 'Could not enumerate Android users'
    printf '%s\n' "$users" | while IFS= read -r user; do
        case "$user" in ''|*[!0-9]*|0?*) fail 'Invalid Android user ID' ;; esac
        [ "$user" -le 21474 ] || fail 'Android user ID is out of range'
        /system/bin/pm list packages -U --user "$user" | awk -v user="$user" '
        /^package:[a-zA-Z0-9_.]+ uid:[0-9]+$/ {
            sub(/^package:/, "", $1); sub(/^uid:/, "", $2)
            if ($2 <= 2147483647 && int($2 / 100000) == user && $2 % 100000 >= 10000 && $2 % 100000 <= 19999) print $2, $1
        }'
    done | sort -k2 -k1n
}
legacy_global() {
    for target in "$SYSTEM_CERTS" "$APEX_CERTS"; do
        [ ! -f "$target/.trustusercerts" ] || return 0
        for pid in $(pidof zygote zygote64 || true); do
            [ ! -f "/proc/$pid/root$target/.trustusercerts" ] || return 0
        done
    done
    return 1
}
status() {
    ready=false
    reason='Open an app to confirm the Zygisk connection.'
    if legacy_global; then
        reason='Legacy global mounts detected. Fully reboot, then restore root and activate the new version.'
    elif [ ! -r "$RUNTIME/current/config" ] || [ ! -d "$RUNTIME/current/global/system" ]; then
        reason='The trust store is not prepared. Tap Reapply and check the log.'
    else
        for marker in "$RUNTIME/zygisk32" "$RUNTIME/zygisk64"; do
            [ -f "$marker" ] || continue
            read -r pid < "$marker" || continue
            case "$pid" in ''|*[!0-9]*) continue ;; esac
            for zygote in $(pidof zygote zygote64 || true); do
                if [ "$pid" = "$zygote" ]; then ready=true; fi
            done
        done
        if [ "$ready" = true ]; then
            reason='Zygisk connected.'
        fi
        if [ -f "$RUNTIME/current/global/enabled" ] && [ -L "$RUNTIME/global.applied" ]; then
            reason="$reason Global CAs active."
        fi
    fi
    rules=$SETTINGS/rules
    [ -f "$rules" ] || rules=$STATE/empty/rules
    cert_tool status "$ready" "$reason" "$rules" "$SETTINGS/certificates" "$STATE/module.log"
}

command=${1:-status}
case "$command" in
    status) [ "$#" = 1 ] || exit 1; status; exit ;;
    apps) [ "$#" = 1 ] || exit 1; app_tool apps "$MODDIR/webroot/app-icons"; exit ;;
    prepare|apply) [ "$#" = 1 ] || exit 1 ;;
    save-policy|import-cert|remove-cert) [ "$#" = 2 ] || exit 1 ;;
    *) fail 'Unknown command' ;;
esac
mkdir "$RUNTIME/.lock" 2>/dev/null || fail 'Another certificate update is running; try again shortly'
WORK=
STAGE=
STOCK_TEMP=
COMMITTED=false
SETTINGS_PUBLISHED=false
GLOBAL_TOUCHED=false
OLD_GLOBAL=
. "$MODDIR/global.sh"
cleanup() {
    result=$?
    trap - EXIT
    if [ "$COMMITTED" = false ]; then
        if [ "$GLOBAL_TOUCHED" = true ]; then
            apply_global "$OLD_GLOBAL" || log 'Could not restore all global mounts; restart Android before trusting the current state'
        fi
        if [ "$SETTINGS_PUBLISHED" = true ]; then
            ln -sf "$SETTINGS" "$STATE/settings.rollback"
            mv -Tf "$STATE/settings.rollback" "$STATE/settings"
        fi
        [ -z "$WORK" ] || rm -rf "$WORK"
    else
        case "$SETTINGS" in "$STATE"/.settings.*) rm -rf "$SETTINGS" ;; esac
    fi
    [ -z "$STAGE" ] || rm -rf "$STAGE"
    [ -z "$STOCK_TEMP" ] || rm -rf "$STOCK_TEMP"
    rm -f "$RUNTIME/current.next" "$RUNTIME/global.applied.next" "$STATE/settings.next"
    rmdir "$RUNTIME/.lock"
    [ "$result" = 0 ] || log "Update failed (exit $result)"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
SETTINGS=$STATE/empty
if [ -L "$STATE/settings" ]; then SETTINGS=$(readlink -f "$STATE/settings"); fi
WORK=$(mktemp -d "$STATE/.settings.XXXXXX")
legacy_global && fail 'Old global CA mounts are still active: fully reboot before using selective trust'
if [ -f "$SETTINGS/rules" ]; then cp "$SETTINGS/rules" "$WORK/rules"; else : > "$WORK/rules"; fi
cp -R "$SETTINGS/certificates" "$WORK/certificates"
case "$command" in
    save-policy)
        [ "${#2}" -le 65536 ] || fail 'Policy is too large'
        printf '%s\n' "$2" > "$WORK/rules"
        ;;
    import-cert) cert_tool import "$WORK/certificates" "$2" > /dev/null ;;
    remove-cert)
        [ "${#2}" -le 32 ] || fail 'Invalid certificate filename'
        case "$2" in *[!0-9a-f.]*) fail 'Invalid certificate filename' ;; esac
        printf '%s\n' "$2" | grep -Eq '^[0-9a-f]{8}\.[0-9]+$' || fail 'Invalid certificate filename'
        [ -f "$WORK/certificates/$2" ] || fail 'Certificate does not exist'
        rm "$WORK/certificates/$2"
        cert_tool drop-cert "$WORK/rules" "$2" > "$WORK/rules.next"
        mv "$WORK/rules.next" "$WORK/rules"
        ;;
esac
app_map > "$WORK/apps"
cert_tool normalize "$WORK/rules" "$WORK/certificates" "$WORK/apps" > "$WORK/rules.next"
mv "$WORK/rules.next" "$WORK/rules"
awk '$1 != "@global" {print $1}' "$WORK/rules" | sort -u > "$WORK/packages"

ZYGOTE=$(pidof zygote64 zygote | awk '{print $1}')
[ -n "$ZYGOTE" ] || fail 'No Zygote found'
# A root shell may inherit a selected app's namespace; only Zygote is a stock source.
STOCK_ROOT=/proc/$ZYGOTE/root
STOCK=$RUNTIME/stock
if [ ! -d "$STOCK" ]; then
    STOCK_TEMP=$(mktemp -d "$RUNTIME/.stock.XXXXXX")
    mkdir "$STOCK_TEMP/system"
    cp "$STOCK_ROOT$SYSTEM_CERTS"/* "$STOCK_TEMP/system/"
    if [ -d "$STOCK_ROOT$APEX_CERTS" ]; then
        mkdir "$STOCK_TEMP/apex"
        cp "$STOCK_ROOT$APEX_CERTS"/* "$STOCK_TEMP/apex/"
    fi
    mv "$STOCK_TEMP" "$STOCK"
    STOCK_TEMP=
fi
STAGE=$(mktemp -d "$RUNTIME/store.XXXXXX")
apex_stock=-
[ ! -d "$STOCK/apex" ] || apex_stock=$STOCK/apex
cert_tool prepare "$STOCK/system" "$apex_stock" "$WORK/rules" "$WORK/certificates" "$WORK/apps" "$STOCK_ROOT/data/misc/user" "$STAGE"
find "$STAGE" -type d -exec chmod 755 '{}' +
find "$STAGE" -type f -exec chmod 644 '{}' +
chown -R 0:0 "$STAGE"
chcon -R u:object_r:system_file:s0 "$STAGE"
for user_store in "$STAGE/global/user" "$STAGE"/apps/*/*/user; do
    [ -d "$user_store" ] || continue
    chcon -R u:object_r:misc_user_data_file:s0 "$user_store"
done

# Publish only fully prepared generations; a process pins one generation at a time.
{ [ ! -f "$SETTINGS/packages" ] || cat "$SETTINGS/packages"; cat "$WORK/packages"; } | sort -u > "$WORK/restart"
OLD_GLOBAL=$STOCK
if [ -L "$RUNTIME/global.applied" ]; then OLD_GLOBAL=$(readlink -f "$RUNTIME/global.applied"); fi
awk '$1 == "@global" {print $2 ($3 == "" ? "" : " " $3)}' "$WORK/rules" > "$WORK/global-certs"
if [ -f "$SETTINGS/global-certs" ]; then cp "$SETTINGS/global-certs" "$WORK/old-global-certs"; else : > "$WORK/old-global-certs"; fi
if [ "$command" = apply ] || ! cmp -s "$WORK/global-certs" "$WORK/old-global-certs" || { [ -s "$WORK/global-certs" ] && [ ! -L "$RUNTIME/global.applied" ]; }; then
    GLOBAL_TOUCHED=true
    apply_global "$STAGE/global" || fail 'Could not apply global certificates; reverting mounts'
fi
ln -s "$WORK" "$STATE/settings.next"
ln -s "$STAGE" "$RUNTIME/current.next"
mv -Tf "$STATE/settings.next" "$STATE/settings"
SETTINGS_PUBLISHED=true
mv -Tf "$RUNTIME/current.next" "$RUNTIME/current"
published=$STAGE
STAGE=
COMMITTED=true
if [ -f "$published/global/enabled" ]; then
    ln -sf "$published/global" "$RUNTIME/global.applied.next"
    mv -Tf "$RUNTIME/global.applied.next" "$RUNTIME/global.applied"
else
    rm -f "$RUNTIME/global.applied"
fi
log "Prepared selective CA store; command=$command"
if [ "$command" != prepare ]; then
    while IFS= read -r package; do
        [ -n "$package" ] || continue
        user=0
        case "$package" in *:*) user=${package%%:*}; package=${package#*:} ;; esac
        case "$user" in ''|*[!0-9]*|0?*) fail 'Invalid restart user ID' ;; esac
        [ "$user" -le 21474 ] || fail 'Restart user ID is out of range'
        printf '%s\n' "$package" | awk 'length <= 255 && /^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$/ {valid=1} END {exit !valid}' || fail 'Invalid restart package'
        # Binder must not receive stdin from the root-only configuration file.
        /system/bin/am force-stop --user "$user" "$package" < /dev/null || fail "Could not stop $user:$package; restart it manually"
    done < "$WORK/restart"
    log 'Selected applications stopped'
fi
# shortcut: immutable snapshots remain in RAM until reboot; reclaim only when namespace users can be tracked.
