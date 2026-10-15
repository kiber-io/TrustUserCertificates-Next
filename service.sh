#!/system/bin/sh
# Prepare after boot; configured global System CAs also update shared trust stores.
while [ "$(getprop sys.boot_completed)" != 1 ]; do
    sleep 1
done
exec sh "${0%/*}/manage.sh" prepare
