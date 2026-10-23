#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?Set ANDROID_HOME to your Android SDK}"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an installed Android NDK}"
: "${JAVA_HOME:?Set JAVA_HOME to an installed JDK 17 or newer}"
export PATH="$JAVA_HOME/bin:$PATH"
build="$PWD/.artifacts/build"
mkdir -p "$build/classes" "$build/dex"
"$JAVA_HOME/bin/javac" --release 8 -cp "$ANDROID_HOME/platforms/android-35/android.jar" -d "$build/classes" tools/java/*.java
"$ANDROID_HOME/build-tools/35.0.0/d8" --min-api 26 --lib "$ANDROID_HOME/platforms/android-35/android.jar" --output "$build/dex" "$build/classes/"*.class
"$JAVA_HOME/bin/jar" cf "$build/cert-tool.jar" -C "$build/dex" classes.dex
cp "$build/dex/classes.dex" "$build/hooks.dex"
bash tools/build-hooks.sh
"$ANDROID_NDK_HOME/ndk-build" NDK_PROJECT_PATH=. \
    APP_BUILD_SCRIPT=native/Android.mk NDK_APPLICATION_MK=native/Application.mk \
    NDK_OUT="$build/obj" NDK_LIBS_OUT="$build/libs"
python3 tools/package.py "$build"
