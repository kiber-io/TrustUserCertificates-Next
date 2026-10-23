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
mkdir -p "$TMP/classes" "$TMP/custom" "$TMP/stock" "$TMP/merged"
"$JAVAC" --release 8 -d "$TMP/classes" "$ROOT/tools/java/CertTool.java"
tool() { "$JAVA" -cp "$TMP/classes" CertTool "$@"; }
reject() {
    if tool import "$TMP/custom" "$(base64 -w0 "$1")" > "$TMP/output" 2> "$TMP/error"; then
        echo "FAIL: accepted $1" >&2
        exit 1
    fi
    [[ ! -s "$TMP/output" && -s "$TMP/error" ]]
}
make_cert() {
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Test CA/O=Testing' \
        -addext "basicConstraints=critical,$2" -addext "keyUsage=critical,$3" \
        -keyout "$TMP/$1.key" -out "$TMP/$1.pem" >/dev/null 2>&1
}
make_cert ca CA:TRUE keyCertSign,cRLSign
make_cert other CA:TRUE keyCertSign,cRLSign
make_cert leaf CA:FALSE digitalSignature
make_cert badusage CA:TRUE digitalSignature
HASH=$(openssl x509 -in "$TMP/ca.pem" -subject_hash_old -noout)
NAME=$(tool import "$TMP/custom" "$(base64 -w0 "$TMP/ca.pem")")
[[ "$NAME" == "$HASH.0" ]]
openssl x509 -in "$TMP/ca.pem" -outform DER -out "$TMP/ca.der"
[[ "$(tool import "$TMP/custom" "$(base64 -w0 "$TMP/ca.der")")" == "$NAME" ]]
sed 's/$/\r/' "$TMP/ca.pem" > "$TMP/crlf.pem"
[[ "$(tool import "$TMP/custom" "$(base64 -w0 "$TMP/crlf.pem")")" == "$NAME" ]]
[[ "$(tool import "$TMP/custom" "$(base64 -w0 "$TMP/other.pem")")" == "$HASH.1" ]]
reject "$TMP/leaf.pem"
reject "$TMP/badusage.pem"
reject "$TMP/ca.key"
cat "$TMP/ca.pem" "$TMP/other.pem" > "$TMP/bundle.pem"
reject "$TMP/bundle.pem"
cat "$TMP/ca.pem" "$TMP/ca.key" > "$TMP/mixed.pem"
reject "$TMP/mixed.pem"
cat "$TMP/ca.der" "$TMP/ca.der" > "$TMP/bundle.der"
reject "$TMP/bundle.der"
printf 'garbage' > "$TMP/garbage"
reject "$TMP/garbage"
head -c 65537 /dev/zero > "$TMP/large"
reject "$TMP/large"

# Stock filename/content must survive a same-subject custom collision.
cp "$TMP/other.pem" "$TMP/stock/$HASH.0"
tool merge "$TMP/stock" "$TMP/custom" "$TMP/merged"
cmp "$TMP/stock/$HASH.0" "$TMP/merged/$HASH.0"
[[ "$(find "$TMP/merged" -type f | wc -l)" == 2 ]]
openssl x509 -in "$TMP/merged/$HASH.1" -outform DER -out "$TMP/merged.der"
cmp "$TMP/ca.der" "$TMP/merged.der"
# An existing duplicate after a deleted slot must not get imported twice.
rm "$TMP/custom/$HASH.0"
[[ "$(tool import "$TMP/custom" "$(base64 -w0 "$TMP/other.pem")")" == "$HASH.1" ]]
[[ "$(find "$TMP/custom" -type f | wc -l)" == 1 ]]
tool list "$TMP/custom" > "$TMP/list.json"
printf 'com.example.one %s.1\n\ncom.example.two %s.1\n@global %s.1\n' "$HASH" "$HASH" "$HASH" > "$TMP/rules"
printf 'line "quoted" \\ slash\nnext\tline\001\n' > "$TMP/log"
tool status true 'a "reason"' "$TMP/rules" "$TMP/custom" "$TMP/log" > "$TMP/status.json"
python3 - "$TMP" "$HASH" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
certs = json.loads((root / 'list.json').read_text())
assert len(certs) == 1
assert certs[0]['name'] == sys.argv[2] + '.1'
assert 'Test CA' in certs[0]['subject']
assert len(certs[0]['fingerprint'].split(':')) == 32
status = json.loads((root / 'status.json').read_text())
assert status['ready'] is True
assert status['reason'] == 'a "reason"'
assert status['packages'] == ['com.example.one', 'com.example.two']
assert status['assignments'] == {name: {sys.argv[2] + '.1': 'system'} for name in status['packages']}
assert status['globalCertificates'] == {sys.argv[2] + '.1': 'system'}
assert status['certificates'] == certs
assert status['log'] == (root / 'log').read_text()
PY
head -c 20000 /dev/zero > "$TMP/log"
tool status false missing "$TMP/rules" "$TMP/custom" "$TMP/log" > "$TMP/status.json"
python3 - "$TMP/status.json" <<'PY'
import json, sys
status = json.load(open(sys.argv[1]))
assert status['ready'] is False and len(status['log']) == 16384
PY

# Each app gets its selected CA plus globals; same-subject stock CAs survive.
[[ "$(tool import "$TMP/custom" "$(base64 -w0 "$TMP/ca.pem")")" == "$HASH.0" ]]
make_cert global CA:TRUE keyCertSign,cRLSign
make_cert appb CA:TRUE keyCertSign,cRLSign
GLOBAL=$(tool import "$TMP/custom" "$(base64 -w0 "$TMP/global.pem")")
APPB=$(tool import "$TMP/custom" "$(base64 -w0 "$TMP/appb.pem")")
printf '10001 com.example.one\n10002 com.example.two\n1000 android\n' > "$TMP/appmap"
# Installed-app inventories span every profile and can exceed the certificate input cap.
python3 - "$TMP/appmap" <<'PY'
import pathlib, sys
with pathlib.Path(sys.argv[1]).open('a') as target:
    for index in range(3000):
        target.write('10003 com.bulk.application' + str(index) + '\n')
PY
[[ $(wc -c < "$TMP/appmap") -gt 65536 ]]
printf 'com.example.two %s\ncom.example.one %s\ncom.example.one %s\n@global %s\n' \
    "$APPB" "$NAME" "$NAME" "$GLOBAL" > "$TMP/rules"
printf '@global %s\ncom.example.one %s\ncom.example.two %s\n' "$GLOBAL" "$NAME" "$APPB" > "$TMP/expected-rules"
tool normalize "$TMP/rules" "$TMP/custom" "$TMP/appmap" > "$TMP/normalized"
cmp "$TMP/expected-rules" "$TMP/normalized"
mkdir "$TMP/prepared" "$TMP/noapex" "$TMP/no-global" "$TMP/empty-policy"
tool prepare "$TMP/stock" "$TMP/stock" "$TMP/rules" "$TMP/custom" "$TMP/appmap" "$TMP/users" "$TMP/prepared"
tool prepare "$TMP/stock" - "$TMP/rules" "$TMP/custom" "$TMP/appmap" "$TMP/users" "$TMP/noapex"
grep -v '^@global ' "$TMP/rules" > "$TMP/app-only-rules"
tool prepare "$TMP/stock" - "$TMP/app-only-rules" "$TMP/custom" "$TMP/appmap" "$TMP/users" "$TMP/no-global"
touch "$TMP/empty-rules"
tool prepare "$TMP/stock" - "$TMP/empty-rules" "$TMP/custom" "$TMP/appmap" "$TMP/users" "$TMP/empty-policy"
[[ -f "$TMP/prepared/global/enabled" && ! -e "$TMP/empty-policy/global/enabled" ]]
[[ ! -e "$TMP/no-global/global/enabled" ]]
[[ ! -s "$TMP/empty-policy/config" && ! -d "$TMP/empty-policy/apps" ]]
[[ -f "$TMP/empty-policy/global/system/.trustusercerts-global" ]]
[[ ! -d "$TMP/noapex/global/apex" && ! -d "$TMP/noapex/apps/0/com.example.one/apex" ]]
printf '10001 com.example.one\n10002 com.example.two\n' > "$TMP/expected-config"
cmp "$TMP/expected-config" "$TMP/prepared/config"
python3 - "$TMP" <<'PY'
import pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
def fingerprint(path):
    return subprocess.check_output(['openssl', 'x509', '-in', str(path), '-noout', '-fingerprint', '-sha256'])
stock, a, b, global_ca = (fingerprint(root / (name + '.pem')) for name in ('other', 'ca', 'appb', 'global'))
for tree in ('prepared', 'noapex', 'no-global'):
    globals = set() if tree == 'no-global' else {global_ca}
    for scope, expected, marker in (
        ('global', {stock} | globals, '.trustusercerts-global'),
        ('apps/0/com.example.one', {stock, a} | globals, '.trustusercerts-app'),
        ('apps/0/com.example.two', {stock, b} | globals, '.trustusercerts-app'),
    ):
        for store in ('system', 'apex') if tree == 'prepared' else ('system',):
            directory = root / tree / scope / store
            assert (directory / marker).is_file()
            actual = {fingerprint(cert) for cert in directory.iterdir() if not cert.name.startswith('.')}
            assert actual == expected, (directory, actual, expected)
            stock_file = next((root / 'stock').iterdir())
            assert (directory / stock_file.name).read_bytes() == stock_file.read_bytes()
PY
tool drop-cert "$TMP/rules" "$NAME" > "$TMP/dropped"
printf '@global %s\ncom.example.two %s\n' "$GLOBAL" "$APPB" > "$TMP/expected-dropped"
cmp "$TMP/expected-dropped" "$TMP/dropped"
tool drop-cert "$TMP/rules" "$GLOBAL" > "$TMP/dropped"
! grep -q '^@global ' "$TMP/dropped"

# The same package in a work profile gets a separate UID, policy key and store.
printf '1010001 com.example.one\n' >> "$TMP/appmap"
cp "$TMP/rules" "$TMP/profile-rules"
printf '10:com.example.one %s\n' "$APPB" >> "$TMP/profile-rules"
tool normalize "$TMP/profile-rules" "$TMP/custom" "$TMP/appmap" > "$TMP/profile-normalized"
grep -q "^com.example.one $NAME$" "$TMP/profile-normalized"
grep -q "^10:com.example.one $APPB$" "$TMP/profile-normalized"
mkdir "$TMP/profiles"
tool prepare "$TMP/stock" "$TMP/stock" "$TMP/profile-rules" "$TMP/custom" "$TMP/appmap" "$TMP/users" "$TMP/profiles"
printf '1010001 com.example.one\n10001 com.example.one\n10002 com.example.two\n' > "$TMP/expected-config"
cmp "$TMP/expected-config" "$TMP/profiles/config"
python3 - "$TMP" <<'PY'
import pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
def fingerprint(path):
    return subprocess.check_output(['openssl', 'x509', '-in', str(path), '-noout', '-fingerprint', '-sha256'])
stock, owner, work, global_ca = (fingerprint(root / (name + '.pem')) for name in ('other', 'ca', 'appb', 'global'))
for user, selected in ((0, owner), (10, work)):
    for store in ('system', 'apex'):
        directory = root / 'profiles/apps' / str(user) / 'com.example.one' / store
        assert {fingerprint(p) for p in directory.iterdir() if not p.name.startswith('.')} == {stock, selected, global_ca}
PY
tool status true ready "$TMP/profile-rules" "$TMP/custom" "$TMP/log" > "$TMP/profiles.json"
python3 - "$TMP/profiles.json" "$NAME" "$APPB" <<'PY'
import json, sys
status = json.load(open(sys.argv[1]))
assert status['assignments']['com.example.one'] == {sys.argv[2]: 'system'}
assert status['assignments']['10:com.example.one'] == {sys.argv[3]: 'system'}
PY

# Modes select the real store, preserve baseline user CAs and deduplicate identical grants.
mkdir -p "$TMP/users/0/cacerts-added" "$TMP/users/10/cacerts-added" "$TMP/modes"
cp "$TMP/other.pem" "$TMP/users/0/cacerts-added/$HASH.0"
cp "$TMP/ca.pem" "$TMP/users/10/cacerts-added/$HASH.0"
printf 'com.example.one %s both\ncom.example.one %s both\n10:com.example.one %s user\n@global %s user\n' \
    "$NAME" "$NAME" "$APPB" "$GLOBAL" > "$TMP/mode-rules"
tool normalize "$TMP/mode-rules" "$TMP/custom" "$TMP/appmap" > "$TMP/mode-normalized"
grep -q "^com.example.one $NAME both$" "$TMP/mode-normalized"
tool prepare "$TMP/stock" "$TMP/stock" "$TMP/mode-rules" "$TMP/custom" "$TMP/appmap" "$TMP/users" "$TMP/modes"
[[ -f "$TMP/modes/global/enabled" && ! -e "$TMP/modes/global/system-enabled" ]]
tool status true ready "$TMP/mode-rules" "$TMP/custom" "$TMP/log" > "$TMP/modes.json"
python3 - "$TMP" "$NAME" "$APPB" "$GLOBAL" <<'PY'
import json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
status = json.loads((root / 'modes.json').read_text())
assert status['assignments'] == {'com.example.one': {sys.argv[2]: 'both'}, '10:com.example.one': {sys.argv[3]: 'user'}}
assert status['globalCertificates'] == {sys.argv[4]: 'user'}
def fingerprint(path):
    return subprocess.check_output(['openssl', 'x509', '-in', str(path), '-noout', '-fingerprint', '-sha256'])
stock, a, b, global_ca = (fingerprint(root / (name + '.pem')) for name in ('other', 'ca', 'appb', 'global'))
for scope, expected in (
    ('global/system', {stock}), ('global/apex', {stock}),
    ('global/user/0', {stock, global_ca}), ('global/user/10', {a, global_ca}),
    ('apps/0/com.example.one/system', {stock, a}), ('apps/0/com.example.one/apex', {stock, a}),
    ('apps/0/com.example.one/user/0', {stock, a, global_ca}),
    ('apps/10/com.example.one/system', {stock}), ('apps/10/com.example.one/apex', {stock}),
    ('apps/10/com.example.one/user/10', {a, b, global_ca}),
):
    directory = root / 'modes' / scope
    actual = {fingerprint(p) for p in directory.iterdir() if not p.name.startswith('.')}
    assert actual == expected, (scope, actual, expected)
stock_name = next((root / 'stock').iterdir()).name
assert (root / 'users/0/cacerts-added' / stock_name).read_bytes() == (root / 'other.pem').read_bytes()
PY
tool drop-cert "$TMP/mode-rules" "$NAME" > "$TMP/mode-dropped"
! grep -q '^com.example.one ' "$TMP/mode-dropped"
grep -q "^10:com.example.one $APPB user$" "$TMP/mode-dropped"

# Off remains a targeted rule even when it is the app's only assignment.
printf 'com.example.one %s off\ncom.example.one %s off\n' "$NAME" "$NAME" > "$TMP/off-rules"
printf 'com.example.one %s off\n' "$NAME" > "$TMP/off-expected"
tool normalize "$TMP/off-rules" "$TMP/custom" "$TMP/appmap" > "$TMP/off-normalized"
cmp "$TMP/off-expected" "$TMP/off-normalized"
mkdir "$TMP/off"
tool prepare "$TMP/stock" "$TMP/stock" "$TMP/off-rules" "$TMP/custom" "$TMP/appmap" "$TMP/users" "$TMP/off"
printf '10001 com.example.one\n' > "$TMP/off-config"
cmp "$TMP/off-config" "$TMP/off/config"
[[ ! -d "$TMP/off/apps/0/com.example.one/user" && ! -f "$TMP/off/global/enabled" ]]
tool status true ready "$TMP/off-rules" "$TMP/custom" "$TMP/log" > "$TMP/off.json"
python3 - "$TMP/off.json" "$NAME" <<'PY'
import json, sys
status = json.load(open(sys.argv[1]))
assert status['assignments'] == {'com.example.one': {sys.argv[2]: 'off'}}
assert status['globalCertificates'] == {}
PY
tool drop-cert "$TMP/off-rules" "$NAME" > "$TMP/off-dropped"
[[ ! -s "$TMP/off-dropped" ]]

# Hooks are separate flags: no certificate library or user CA baseline is required.
mkdir "$TMP/hook-custom" "$TMP/hooks"
printf 'com.example.one @hooks ct\n10:com.example.one @hooks user\ncom.example.one @hooks ct\n' > "$TMP/hook-rules"
printf '10:com.example.one @hooks user\ncom.example.one @hooks ct\n' > "$TMP/hook-expected"
tool normalize "$TMP/hook-rules" "$TMP/hook-custom" "$TMP/appmap" > "$TMP/hook-normalized"
cmp "$TMP/hook-expected" "$TMP/hook-normalized"
tool prepare "$TMP/stock" "$TMP/stock" "$TMP/hook-rules" "$TMP/hook-custom" "$TMP/appmap" "$TMP/no-user-baseline" "$TMP/hooks"
tool status true ready "$TMP/hook-rules" "$TMP/hook-custom" "$TMP/log" > "$TMP/hooks.json"
python3 - "$TMP" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
status = json.loads((root / 'hooks.json').read_text())
assert status['assignments'] == {} and status['globalCertificates'] == {} and status['certificates'] == []
assert status['packages'] == ['10:com.example.one', 'com.example.one']
assert status['hooks'] == {
    'com.example.one': {'disableCT': True, 'trustUserCAs': False, "trustSystemCAs": False},
    '10:com.example.one': {'disableCT': False, 'trustUserCAs': True, "trustSystemCAs": False},
}
assert (root / 'hooks/config').read_text() == '1010001 com.example.one\n10001 com.example.one\n'
stock_file = next((root / 'stock').iterdir())
for user, flag in ((0, b'\x01'), (10, b'\x02')):
    app = root / ('hooks/apps/%s/com.example.one' % user)
    assert (app / 'hooks').is_file() and (app / 'hooks').read_bytes() == flag
    assert not (app / 'user').exists()
    for store in ('system', 'apex'):
        files = [p for p in (app / store).iterdir() if not p.name.startswith('.')]
        assert len(files) == 1 and files[0].read_bytes() == stock_file.read_bytes()
assert not (root / 'hooks/global/enabled').exists()
assert not (root / 'no-user-baseline').exists()
PY
cp "$TMP/hook-rules" "$TMP/hook-and-cert"
printf 'com.example.one %s\n' "$NAME" >> "$TMP/hook-and-cert"
tool drop-cert "$TMP/hook-and-cert" "$NAME" > "$TMP/hook-dropped"
cmp "$TMP/hook-expected" "$TMP/hook-dropped"

reject_rules() {
    if tool normalize "$TMP/bad-rules" "$TMP/custom" "$TMP/appmap" > "$TMP/output" 2> "$TMP/error"; then
        echo 'FAIL: accepted invalid certificate rules' >&2
        exit 1
    fi
    [[ ! -s "$TMP/output" && -s "$TMP/error" ]]
}
for RULE in "com.unknown.app $NAME" "com.example.one deadbeef.0" \
    "../com.example.one $NAME" "com.example.one ../$NAME" \
    "com.example.one $NAME extra" 'com.example.one' "@global ../$NAME" \
    "com.example.one $NAME System" "com.example.one $NAME user extra" \
    "com.example.one $NAME inherit" "@global $NAME off" \
    '@global @hooks both' 'com.example.one @hooks' 'com.example.one @hooks off' \
    'com.example.one @hooks unknown' 'com.example.one @hooks CT' 'com.example.one @hooks ct,user' \
    'com.example.one @hooks ct extra' 'com.unknown.app @hooks ct' '10:../com.example.one @hooks ct' \
    "0:com.example.one $NAME" "01:com.example.one $NAME" "-1:com.example.one $NAME" \
    "21475:com.example.one $NAME" "9999999999999:com.example.one $NAME" \
    "11:com.example.one $NAME" "10:../com.example.one $NAME" "10:com.example.one;id $NAME"; do
    printf '%s\n' "$RULE" > "$TMP/bad-rules"
    reject_rules
done
for MODE in off user both; do
    printf 'com.example.one %s system\ncom.example.one %s %s\n' "$NAME" "$NAME" "$MODE" > "$TMP/bad-rules"
    reject_rules
done
printf 'com.example.one @hooks ct\ncom.example.one @hooks user\n' > "$TMP/bad-rules"
reject_rules
head -c 65537 /dev/zero > "$TMP/bad-rules"
reject_rules
printf '\000com.example.one %s\n' "$NAME" > "$TMP/bad-rules"
reject_rules
printf 'com.example.one %s\n' "$NAME" > "$TMP/bad-rules"
printf '20001 com.example.one\n' > "$TMP/appmap"
reject_rules
printf '10001 com.example.one\n10002 com.example.one\n' > "$TMP/appmap"
reject_rules
echo 'PASS: certificate validation, hashes, per-user/app/global modes, normalization, stock/user preservation and status'
