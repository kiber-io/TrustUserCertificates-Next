#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${ANDROID_HOME:?Set ANDROID_HOME to your Android SDK}"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an installed Android NDK}"
: "${JAVA_HOME:?Set JAVA_HOME to JDK 17 or newer}"
export PATH="$JAVA_HOME/bin:$PATH"
src="$PWD/tests/hook-probe"
out="$PWD/.artifacts/hook-probe"
sdk="$ANDROID_HOME/build-tools/35.0.0"
platform="$ANDROID_HOME/platforms/android-36/android.jar"
llvm="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
mkdir -p "$out/classes" "$out/dex" "$out/lib"
for entry in arm64-v8a:aarch64-linux-android armeabi-v7a:armv7a-linux-androideabi x86_64:x86_64-linux-android x86:i686-linux-android; do
    abi=${entry%%:*}; target=${entry#*:}
    mkdir -p "$out/lib/$abi"
    "$llvm/${target}26-clang++" -shared -fPIC -Os -Wall -Wextra -Werror -nostdlib++ \
        -Wl,-z,max-page-size=16384 "$src/reader.cpp" -o "$out/lib/$abi/libtuc-probe.so"
    "$llvm/llvm-strip" --strip-unneeded "$out/lib/$abi/libtuc-probe.so"
done
javac --release 8 -cp "$platform" -d "$out/classes" "$src/ProbeActivity.java"
"$sdk/d8" --min-api 26 --lib "$platform" --output "$out/dex" "$out/classes/io/kiber/tuc/probe/"*.class
"$sdk/aapt2" compile --dir "$src/res" -o "$out/resources.zip"
"$sdk/aapt2" link -I "$platform" --manifest "$src/AndroidManifest.xml" "$out/resources.zip" -o "$out/unsigned.apk"
python3 - "$out" <<'PY'
from pathlib import Path
import sys, zipfile
out = Path(sys.argv[1])
with zipfile.ZipFile(out / 'unsigned.apk', 'a', zipfile.ZIP_DEFLATED) as apk:
    apk.write(out / 'dex/classes.dex', 'classes.dex')
    for lib in sorted((out / 'lib').rglob('*.so')):
        apk.write(lib, lib.relative_to(out))
PY
"$sdk/zipalign" -f -P 16 4 "$out/unsigned.apk" "$out/aligned.apk"
if [[ ! -f "$out/debug.keystore" ]]; then
    keytool -genkeypair -keystore "$out/debug.keystore" -storepass android -keypass android \
        -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 -dname 'CN=TUC Hook Probe Debug'
fi
"$sdk/apksigner" sign --ks "$out/debug.keystore" --ks-pass pass:android \
    --out "$PWD/.artifacts/tuc-hook-probe.apk" "$out/aligned.apk"
"$sdk/apksigner" verify "$PWD/.artifacts/tuc-hook-probe.apk"
echo "$PWD/.artifacts/tuc-hook-probe.apk"
