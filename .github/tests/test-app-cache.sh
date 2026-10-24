#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
serial=${1:?Usage: test-app-cache.sh ROOTED_DEVICE_SERIAL}
: "${JAVA_HOME:?Set JAVA_HOME to JDK 17 or newer}"
: "${ANDROID_HOME:?Set ANDROID_HOME}"
export PATH="$JAVA_HOME/bin:$PATH"
work=$(mktemp -d)
remote=''
cleanup() {
    rm -rf "$work"
    if [[ -n "$remote" ]]; then adb -s "$serial" shell "rm -rf $remote" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
mkdir "$work/classes" "$work/dex"
javac --release 8 -cp "$ANDROID_HOME/platforms/android-35/android.jar" -d "$work/classes" tests/java/AppToolCacheTest.java
"$ANDROID_HOME/build-tools/35.0.0/d8" --min-api 26 --lib "$ANDROID_HOME/platforms/android-35/android.jar" \
    --output "$work/dex" "$work/classes/AppToolCacheTest.class"
jar cf "$work/test.jar" -C "$work/dex" classes.dex
candidate=$(adb -s "$serial" shell mktemp -d /data/local/tmp/tuc-cache-test-XXXXXXXX | tr -d '\r')
[[ "$candidate" =~ ^/data/local/tmp/tuc-cache-test-[A-Za-z0-9]+$ ]] || { echo 'Invalid device temporary directory' >&2; exit 1; }
remote=$candidate
adb -s "$serial" push "$work/test.jar" "$remote/test.jar" >/dev/null
adb -s "$serial" shell "su -c 'CLASSPATH=/data/adb/modules/trustusercerts/cert-tool.jar:$remote/test.jar /system/bin/app_process / AppToolCacheTest $remote'"
