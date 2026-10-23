#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?Set ANDROID_HOME}"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME}"
cmake="$ANDROID_HOME/cmake/3.31.0/bin/cmake"
ninja="${NINJA_EXECUTABLE:-$(command -v ninja || true)}"
if [ -z "$ninja" ]; then ninja="$ANDROID_HOME/cmake/3.31.0/bin/ninja"; fi
if ! "$ninja" --version | awk -F. '{ exit !($1 > 1 || ($1 == 1 && $2 >= 11)) }'; then
    echo "Hook build requires Ninja >=1.11; set NINJA_EXECUTABLE or install ninja on PATH" >&2
    exit 1
fi
build="$PWD/.artifacts/build/hooks"
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
    "$cmake" -S native/hooks -B "$build/$abi" -G Ninja \
        -DCMAKE_MAKE_PROGRAM="$ninja" \
        -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$abi" -DANDROID_PLATFORM=android-26 -DANDROID_STL=c++_static \
        -DCMAKE_BUILD_TYPE=Release
    "$cmake" --build "$build/$abi" --target tuc-hooks --parallel 4
    mkdir -p "$build/$abi/package"
    "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip" \
        --strip-unneeded -o "$build/$abi/package/libtuc-hooks.so" "$build/$abi/libtuc-hooks.so"
done
