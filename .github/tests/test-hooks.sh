#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
JDK=${JAVA_HOME:-/opt/agent-tools-runtimes/runtime/jdk/17}
JAVAC=${JAVAC:-$JDK/bin/javac}
JAVA=${JAVA:-$JDK/bin/java}
[[ -x "$JAVAC" ]] || JAVAC=javac
[[ -x "$JAVA" ]] || JAVA=java
"$JAVAC" --release 8 -d "$TMP" "$ROOT/tools/java/HookBridge.java" \
    "$ROOT/tests/java/android/security/net/config/NetworkSecurityConfig.java" "$ROOT/tests/java/HookBridgeTest.java"
"$JAVA" -cp "$TMP" HookBridgeTest
