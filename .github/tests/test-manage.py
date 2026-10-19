#!/usr/bin/env python3
"""Exercise the shipped management script against temporary stores, never a device."""
import base64
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
JDK = Path(os.environ.get("JAVA_HOME", "/opt/agent-tools-runtimes/runtime/jdk/17"))
JAVA = os.environ.get("JAVA", str(JDK / "bin/java") if (JDK / "bin/java").exists() else "java")
JAVAC = os.environ.get("JAVAC", str(JDK / "bin/javac") if (JDK / "bin/javac").exists() else "javac")


class ManageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory(prefix="trust-certs-fixture-")
        cls.fixture = Path(cls.shared.name)
        cls.classes = cls.fixture / "classes"
        cls.classes.mkdir()
        subprocess.run([JAVAC, "--release", "8", "-d", str(cls.classes),
                        str(ROOT / "tools/java/CertTool.java")], check=True)
        cls.certificates = []
        for name in ("Stock", "First", "Second", "Global"):
            pem = cls.fixture / (name + ".pem")
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-subj", "/CN=" + name,
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", str(cls.fixture / (name + ".key")), "-out", str(pem),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            digest = subprocess.check_output([
                "openssl", "x509", "-in", str(pem), "-subject_hash_old", "-noout",
            ], text=True).strip()
            cls.certificates.append((digest + ".0", pem.read_bytes()))

    @classmethod
    def tearDownClass(cls):
        cls.shared.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="trust-certs-manage-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "state"
        self.runtime = self.root / "runtime"
        self.stock = self.root / "system"
        self.apex = self.root / "apex"
        for directory in (self.stock, self.apex):
            directory.mkdir()
            (directory / self.certificates[0][0]).write_bytes(self.certificates[0][1])
        self.user_base = self.root / "users"
        self.user_base.mkdir()
        self.stops = self.root / "stops"
        self.stops.touch()
        self.global_calls = self.root / "global-calls"
        self.global_calls.touch()
        self.forbidden = self.root / "forbidden"
        self.env = dict(os.environ, ASH_STANDALONE="1", KSU="true",
                        PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        CHCON_LOG=str(self.root / "labels"), STOPS=str(self.stops), STOPS_PROFILES=str(self.root / "stops-profiles"), FORBIDDEN=str(self.forbidden),
                        GLOBAL_CALLS=str(self.global_calls), GLOBAL_FAILURE_SEEN=str(self.root / "global-failed"),
                        TEST_CLASSES=str(self.classes), TEST_JAVA=shutil.which(JAVA))
        self.mock("id", "printf '0\\n'\n")
        self.mock("chown", "exit 0\n")
        self.mock("pidof", "printf '1\\n'\n")
        self.mock("chcon", '''printf '%s\\n' "$*" >> "$CHCON_LOG"
if [ "${FAIL_MOUNTPOINT_CHCON:-0}" = 1 ] && [ "$#" = 2 ]; then exit 1; fi
case "$*" in *misc_user_data_file*) [ "${FAIL_USER_CHCON:-0}" != 1 ] || exit 1 ;; esac
[ "${FAIL_CHCON:-0}" != 1 ]
''')
        self.mock("pm", '''[ "${FAIL_PM:-0}" != 1 ] || exit 1
if [ "$1 $2" = 'list users' ]; then
    printf 'Users:\\n    UserInfo{0:Owner:13} running\\n'
    if [ "${MULTI_USER:-0}" = 1 ]; then printf '    UserInfo{10:Work:30} running\\n'; fi
    if [ -n "${BAD_USER:-}" ]; then printf '    UserInfo{%s:Invalid:30} running\\n' "$BAD_USER"; fi
elif [ "$5" = 0 ]; then
    printf 'package:com.first.app uid:10001\\npackage:com.second.app uid:10002\\npackage:com.unsupported.app uid:99999\\n'
elif [ "$5" = 10 ]; then
    printf 'package:com.first.app uid:1010001\\npackage:com.second.app uid:1010002\\n'
else
    exit 1
fi
''')
        self.mock("am", '''[ "$(readlink /proc/self/fd/0)" = /dev/null ] || exit 2
printf '%s\\n' "$4" >> "$STOPS"
printf '%s:%s\\n' "$3" "$4" >> "$STOPS_PROFILES"
''')
        self.mock("app_process", '''tool=$2
shift 2
if [ "$tool" = AppTool ]; then
    printf '[{"package":"com.first.app","label":"Первое","uid":10001},{"package":"com.second.app","label":"Второе","uid":10002}]\\n'
    exit 0
fi
if [ "$1" = prepare ] && [ "${FAIL_MERGE:-0}" = 1 ]; then exit 1; fi
exec "$TEST_JAVA" -cp "$TEST_CLASSES" CertTool "$@"
''')
        self.mock("mv", '''if [ "${FAIL_PUBLISH:-0}" = 1 ]; then
    for arg do case "$arg" in */runtime/current.next) exit 1 ;; esac; done
fi
if [ "${FAIL_MARKER:-0}" = 1 ]; then
    for arg do case "$arg" in */runtime/global.applied.next) exit 1 ;; esac; done
fi
exec ''' + shlex.quote(shutil.which("mv")) + ' "$@"\n')
        for name in ("mount", "umount", "nsenter", "unshare"):
            self.mock(name, 'printf \'%s\\n\' "$0" >> "$FORBIDDEN"\nexit 99\n')

        # Keep all control flow from manage.sh; relocate only Android paths/dependencies.
        source = (ROOT / "manage.sh").read_text()
        replacements = {
            "/data/adb/ksu/bin/busybox": "/bin/sh",
            "/data/adb/magisk/busybox": "/bin/sh",
            "/data/adb/trustusercerts": str(self.state),
            "/data/misc/user": str(self.user_base),
            "/dev/trustusercerts": str(self.runtime),
            "/system/etc/security/cacerts": str(self.stock),
            "/apex/com.android.conscrypt/cacerts": str(self.apex),
        }
        for name in ("pm", "am", "app_process"):
            replacements["/system/bin/" + name] = name
        for old, new in replacements.items():
            source = source.replace(old, new)
        source = source.replace("STOCK_ROOT=/proc/$ZYGOTE/root", "STOCK_ROOT=")
        shutil.copyfile(ROOT / "global.sh", self.root / "global.sh")
        source = source.replace('. "$MODDIR/global.sh"', '''. "$MODDIR/global.sh"
apply_global() {
    printf '%s\\n' "$1" >> "$GLOBAL_CALLS"
    if [ "${FAIL_GLOBAL:-0}" = 1 ] && [ ! -f "$GLOBAL_FAILURE_SEEN" ]; then
        touch "$GLOBAL_FAILURE_SEEN"
        return 1
    fi
}
''')
        # Some CI/container temporary mounts prohibit executing files; functions
        # dispatch mock scripts through sh while preserving their argument lists.
        functions = "\n".join(
            name + '() { /bin/sh ' + shlex.quote(str(path)) + ' "$@"; }'
            for path in self.bin.iterdir() for name in [path.name]
        )
        self.script = self.root / "manage.sh"
        self.script.write_text(functions + "\n" + source)

    def mock(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    def run_manage(self, *args, success=True, **extra_env):
        result = subprocess.run(["bash", str(self.script), *args],
                                env=dict(self.env, **extra_env), text=True,
                                capture_output=True, timeout=30)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.forbidden.exists(), "Only the mocked global helper may enter namespaces")
        self.assertFalse((self.runtime / ".lock").exists(), "Update leaked its lock")
        return result

    def status(self):
        return json.loads(self.run_manage("status").stdout)

    def import_ca(self, index=1):
        self.run_manage("import-cert", base64.b64encode(self.certificates[index][1]).decode())

    def policy(self, *records, **options):
        return self.run_manage("save-policy", "\n".join(records), **options)

    def ca_names(self, path):
        return {p.name for p in path.iterdir() if re.fullmatch(r"[0-9a-f]{8}\.[0-9]+", p.name)}

    def user_baseline(self, user, cert_index):
        directory = self.user_base / str(user) / "cacerts-added"
        directory.mkdir(parents=True)
        name, data = self.certificates[cert_index]
        (directory / name).write_bytes(data)
        return directory

    def snapshot(self):
        settings = self.state / "settings"
        current = self.runtime / "current"
        return (os.readlink(settings), os.readlink(current),
                (settings / "rules").read_bytes(),
                {p.name: p.read_bytes() for p in (settings / "certificates").iterdir()},
                (current / "config").read_bytes(),
                os.readlink(self.runtime / "global.applied") if (self.runtime / "global.applied").is_symlink() else None,
                {str(p.relative_to(current)): p.read_bytes() for p in current.rglob("*") if p.is_file()})

    def test_empty_default_and_prepare(self):
        status = self.status()
        self.assertFalse(status["ready"])
        self.assertEqual(status["packages"], [])
        self.assertEqual(status["assignments"], {})
        self.assertEqual(status["globalCertificates"], {})
        self.assertEqual(status["certificates"], [])
        self.run_manage("prepare")
        self.assertEqual((self.runtime / "current/config").read_text(), "")
        self.assertEqual(self.stops.read_text(), "")
        self.assertEqual(self.ca_names(self.runtime / "current/global/system"), {self.certificates[0][0]})
        self.assertEqual(self.global_calls.read_text(), "")
        apps = json.loads(self.run_manage("apps").stdout)
        self.assertEqual(apps[0]["label"], "Первое")
        source = (ROOT / "manage.sh").read_text()
        self.assertIn('$STOCK_ROOT/data/misc/user', source, "User CA baselines must come from Zygote")

    def test_import_per_app_restart_union_and_remove(self):
        self.import_ca()
        first = self.certificates[1][0]
        self.assertEqual(len(self.status()["certificates"]), 1)
        self.assertEqual(self.status()["assignments"], {}, "Import must never grant trust automatically")
        self.assertEqual(self.status()["globalCertificates"], {})
        self.policy("com.first.app " + first)
        self.assertEqual((self.runtime / "current/config").read_text(), "10001 com.first.app\n")
        for name in ("system", "apex"):
            self.assertEqual(self.ca_names(self.runtime / "current/apps/0/com.first.app" / name),
                             {self.certificates[0][0], first})
        self.stops.write_text("")
        self.policy("com.second.app " + first)
        self.assertEqual(self.stops.read_text().splitlines(), ["com.first.app", "com.second.app"])
        self.assertEqual(self.status()["packages"], ["com.second.app"])
        self.assertEqual(self.status()["assignments"], {"com.second.app": {first: "system"}})
        self.run_manage("remove-cert", first)
        self.assertEqual(self.status()["certificates"], [])
        self.assertEqual(self.status()["assignments"], {})
        self.assertEqual(self.ca_names(self.runtime / "current/global/system"), {self.certificates[0][0]})
        self.assertEqual(self.global_calls.read_text(), "")

    def test_work_profile_same_package_has_independent_grants_and_targeted_restart(self):
        self.env["MULTI_USER"] = "1"
        for index in (1, 2, 3):
            self.import_ca(index)
        stock, owner, work, globally = [cert[0] for cert in self.certificates]
        details = self.root / "stops-profiles"
        self.policy("10:com.first.app " + work)
        self.assertEqual(details.read_text().splitlines(), ["10:com.first.app"])
        self.assertFalse((self.runtime / "current/apps/0/com.first.app").exists())
        self.assertEqual((self.runtime / "current/config").read_text(), "1010001 com.first.app\n")
        self.policy("com.first.app " + owner, "10:com.first.app " + work, "@global " + globally)
        status = self.status()
        self.assertEqual(status["assignments"], {"com.first.app": {owner: "system"}, "10:com.first.app": {work: "system"}})
        self.assertEqual(status["packages"], ["10:com.first.app", "com.first.app"])
        self.assertEqual((self.runtime / "current/config").read_text(),
                         "1010001 com.first.app\n10001 com.first.app\n")
        for store in ("system", "apex"):
            self.assertEqual(self.ca_names(self.runtime / "current/apps/0/com.first.app" / store),
                             {stock, owner, globally})
            self.assertEqual(self.ca_names(self.runtime / "current/apps/10/com.first.app" / store),
                             {stock, work, globally})
        self.assertIn("com.first.app " + owner, (self.state / "settings/rules").read_text())
        details.write_text("")
        # Removing the owner assignment stops its old process, and keeps the work UID distinct.
        self.policy("10:com.first.app " + work, "@global " + globally)
        self.assertEqual(details.read_text().splitlines(), ["10:com.first.app", "0:com.first.app"])
        details.write_text("")
        self.run_manage("apply")
        self.assertEqual(details.read_text().splitlines(), ["10:com.first.app"])

    def test_invalid_profile_ids_do_not_change_policy_or_stop_any_app(self):
        self.env["MULTI_USER"] = "1"
        self.import_ca()
        self.policy("com.first.app " + self.certificates[1][0])
        before = self.snapshot()
        details = self.root / "stops-profiles"
        details.write_text("")
        for key in ("0:com.first.app", "01:com.first.app", "-1:com.first.app",
                    "21475:com.first.app", "9999999999999:com.first.app",
                    "10:../com.first.app", "10:com.first.app;id", "10:0:com.first.app",
                    "11:com.first.app"):
            with self.subTest(key=key):
                self.policy(key + " " + self.certificates[1][0], success=False)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(details.read_text(), "")
        for user in ("10;id", "-1", "01", "21475", "99999999999999999999999999999"):
            with self.subTest(user=user):
                self.run_manage("apply", success=False, BAD_USER=user)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(details.read_text(), "")

    def test_invalid_inputs_preserve_published_generations(self):
        self.import_ca()
        before = self.snapshot()
        first = self.certificates[1][0]
        for args in (("save-policy", "com.first.app;echo bad " + first),
                     ("save-policy", "com.not.installed " + first),
                     ("save-policy", "com.unsupported.app " + first),
                     ("save-policy", "com.first.app deadbeef.0"),
                     ("save-policy", "@global ../../escape"),
                     ("save-policy", "@global " + first + " extra"),
                     ("save-policy", "com.first.app " + first + " none"),
                     ("save-policy", "com.first.app " + first + " user extra"),
                     ("save-policy", "@global " + first + " off"),
                     ("save-policy", "com.first.app " + first + " inherit"),
                     ("save-policy", "com.first.app " + first + " off\ncom.first.app " + first),
                     ("save-policy", "com.first.app " + first + " system\ncom.first.app " + first + " user"),
                     ("import-cert", "Z2FyYmFnZQ=="),
                     ("remove-cert", "../../module.prop"),
                     ("remove-cert", self.certificates[1][0] + "\ninvalid"),
                     ("save-policy",), ("unknown",)):
            with self.subTest(args=args):
                self.run_manage(*args, success=False)
                self.assertEqual(self.snapshot(), before)

    def test_local_overrides_replace_globals_and_removing_override_restores_inheritance(self):
        self.env["MULTI_USER"] = "1"
        self.import_ca()
        baseline0 = self.user_baseline(0, 0)
        baseline10 = self.user_baseline(10, 0)
        stock, first = [cert[0] for cert in self.certificates[:2]]
        current = self.runtime / "current"
        # The owner copy opts out; the work copy has no local entry and inherits globally.
        self.policy("@global " + first, "com.first.app " + first + " off")
        self.assertEqual(self.status()["assignments"], {"com.first.app": {first: "off"}})
        self.assertEqual((current / "config").read_text(), "10001 com.first.app\n")
        self.assertFalse((current / "apps/10/com.first.app").exists())
        self.assertFalse((current / "apps/0/com.first.app/user").exists())
        for store in ("system", "apex"):
            self.assertEqual(self.ca_names(current / "global" / store), {stock, first})
            self.assertEqual(self.ca_names(current / "apps/0/com.first.app" / store), {stock})
        self.assertEqual((self.root / "stops-profiles").read_text().splitlines(), ["0:com.first.app"])

        # User narrows global Both, rather than adding User on top of global System.
        self.policy("@global " + first + " both", "com.first.app " + first + " user")
        for store in ("system", "apex"):
            self.assertEqual(self.ca_names(current / "apps/0/com.first.app" / store), {stock})
        self.assertEqual(self.ca_names(current / "apps/0/com.first.app/user/0"), {stock, first})
        self.assertEqual(self.ca_names(current / "global/user/10"), {stock, first})

        # System replaces global User and needs no user overlay for the selected copy.
        self.policy("@global " + first + " user", "com.first.app " + first)
        self.assertEqual(self.ca_names(current / "apps/0/com.first.app/system"), {stock, first})
        self.assertFalse((current / "apps/0/com.first.app/user").exists())
        self.assertEqual(self.ca_names(current / "global/system"), {stock})
        self.assertEqual(self.ca_names(current / "global/user/0"), {stock, first})

        # Off cancels both injected stores; Android's actual user CAs stay untouched.
        self.policy("@global " + first + " both", "com.first.app " + first + " off")
        self.assertEqual(self.ca_names(current / "apps/0/com.first.app/system"), {stock})
        self.assertFalse((current / "apps/0/com.first.app/user").exists())
        self.assertEqual((baseline0 / stock).read_bytes(), self.certificates[0][1])
        self.assertEqual((baseline10 / stock).read_bytes(), self.certificates[0][1])
        self.assertIn("com.first.app " + first + " off", (self.state / "settings/rules").read_text().splitlines())
        self.stops.write_text("")
        self.policy("@global " + first + " both")
        self.assertEqual(self.status()["assignments"], {})
        self.assertEqual((current / "config").read_text(), "")
        self.assertFalse((current / "apps").exists())
        self.assertEqual(self.ca_names(current / "global/system"), {stock, first})
        self.assertEqual(self.ca_names(current / "global/user/0"), {stock, first})
        self.assertEqual(self.stops.read_text().splitlines(), ["com.first.app"])
        self.policy("@global " + first + " both", "com.first.app " + first + " off")
        self.run_manage("remove-cert", first)
        self.assertEqual(self.status()["assignments"], {})
        self.assertEqual(self.status()["globalCertificates"], {})
        self.assertEqual((current / "config").read_text(), "")

    def test_off_only_is_a_targeted_rule_and_preserves_cas_already_in_android(self):
        self.import_ca(0)
        baseline = self.user_baseline(0, 0)
        stock = self.certificates[0][0]
        self.policy("com.first.app " + stock + " off", "com.first.app " + stock + " off")
        self.assertEqual((self.runtime / "current/config").read_text(), "10001 com.first.app\n")
        self.assertEqual(self.status()["assignments"], {"com.first.app": {stock: "off"}})
        for store in ("system", "apex"):
            self.assertEqual(self.ca_names(self.runtime / "current/apps/0/com.first.app" / store), {stock})
        self.assertEqual(self.ca_names(baseline), {stock})
        self.assertEqual((baseline / stock).read_bytes(), self.certificates[0][1])
        self.assertFalse((self.runtime / "current/global/enabled").exists())
        self.assertFalse((self.runtime / "current/apps/0/com.first.app/user").exists())
        self.assertEqual((self.state / "settings/rules").read_text(), "com.first.app " + stock + " off\n")

    def test_system_user_and_both_modes_per_profile_without_user_store_writes(self):
        self.env["MULTI_USER"] = "1"
        for index in (1, 2):
            self.import_ca(index)
        baseline0 = self.user_baseline(0, 3)
        baseline10 = self.user_baseline(10, 0)
        original = {str(p): p.read_bytes() for p in self.user_base.rglob("*") if p.is_file()}
        stock, first, globally, existing0 = [cert[0] for cert in self.certificates]
        self.policy("com.first.app " + first + " system", "10:com.first.app " + first + " user",
                    "@global " + globally + " user")
        current = self.runtime / "current"
        self.assertTrue((current / "global/enabled").exists())
        self.assertFalse((current / "global/system-enabled").exists())
        for store in ("system", "apex"):
            self.assertEqual(self.ca_names(current / "global" / store), {stock})
            self.assertEqual(self.ca_names(current / "apps/0/com.first.app" / store), {stock, first})
            self.assertEqual(self.ca_names(current / "apps/10/com.first.app" / store), {stock})
        self.assertEqual(self.ca_names(current / "global/user/0"), {existing0, globally})
        self.assertEqual(self.ca_names(current / "global/user/10"), {stock, globally})
        self.assertEqual(self.ca_names(current / "apps/0/com.first.app/user/0"), {existing0, globally})
        self.assertEqual(self.ca_names(current / "apps/10/com.first.app/user/10"), {stock, first, globally})
        self.assertFalse((current / "apps/10/com.first.app/user/0").exists())
        status = self.status()
        self.assertEqual(status["assignments"], {"com.first.app": {first: "system"}, "10:com.first.app": {first: "user"}})
        self.assertEqual(status["globalCertificates"], {globally: "user"})
        self.assertIn("com.first.app " + first, (self.state / "settings/rules").read_text().splitlines())
        self.assertIn("misc_user_data_file:s0", (self.root / "labels").read_text())
        for source in (baseline0 / existing0, baseline10 / stock):
            user = source.parent.parent.name
            self.assertEqual(source.read_bytes(), (current / "global/user" / user / source.name).read_bytes())

        # A local user grant replaces global System; explicit Both keeps both stores.
        self.policy("com.first.app " + first + " user", "10:com.first.app " + first + " both",
                    "@global " + first, "@global " + globally + " user")
        self.assertTrue((current / "global/system-enabled").exists())
        for user, baseline in ((0, existing0), (10, stock)):
            self.assertEqual(self.ca_names(current / ("apps/%s/com.first.app/system" % user)),
                             {stock} if user == 0 else {stock, first})
            self.assertEqual(self.ca_names(current / ("apps/%s/com.first.app/user/%s" % (user, user))),
                             {baseline, first, globally})
        # Baselines are refreshed for each snapshot, including additions made outside this module.
        (baseline0 / stock).write_bytes(self.certificates[0][1])
        original[str(baseline0 / stock)] = self.certificates[0][1]
        self.run_manage("apply")
        self.assertIn(stock, self.ca_names(current / "global/user/0"))
        self.run_manage("remove-cert", first)
        self.assertEqual(self.status()["assignments"], {})
        self.assertEqual(self.status()["globalCertificates"], {globally: "user"})
        self.assertFalse((current / "global/system-enabled").exists())
        self.assertFalse((current / "apps").exists())
        self.assertEqual(original, {str(p): p.read_bytes() for p in self.user_base.rglob("*") if p.is_file()})

    def test_global_user_modes_initialize_empty_profile_mountpoints_without_installing_cas(self):
        self.env["MULTI_USER"] = "1"
        self.import_ca()
        baseline = self.user_baseline(0, 0)
        (self.user_base / "10").mkdir()
        stock, first = [cert[0] for cert in self.certificates[:2]]
        for mode in ("user", "both"):
            self.policy("@global " + first + " " + mode)
            empty = self.user_base / "10/cacerts-added"
            self.assertTrue(empty.is_dir())
            self.assertEqual(empty.stat().st_mode & 0o777, 0o755)
            self.assertEqual(list(empty.iterdir()), [], "Module CAs must not enter Android's real store")
            self.assertEqual((baseline / stock).read_bytes(), self.certificates[0][1])
            self.assertEqual(self.ca_names(self.runtime / "current/global/user/10"), {first})
            self.assertEqual(self.ca_names(self.runtime / "current/global/user/0"), {stock, first})

    def test_failed_empty_profile_setup_removes_only_new_mountpoints(self):
        self.env["MULTI_USER"] = "1"
        self.import_ca()
        self.user_baseline(0, 0)
        (self.user_base / "10").mkdir()
        first = self.certificates[1][0]
        before = self.snapshot()
        for failure in ("FAIL_MOUNTPOINT_CHCON", "FAIL_GLOBAL", "FAIL_PUBLISH"):
            with self.subTest(failure=failure):
                self.policy("@global " + first + " user", success=False, **{failure: "1"})
                self.assertEqual(self.snapshot(), before)
                self.assertFalse((self.user_base / "10/cacerts-added").exists())
                self.assertTrue((self.user_base / "10").is_dir())
                self.assertTrue((self.user_base / "0/cacerts-added").is_dir())

    def test_missing_user_baseline_and_user_label_failure_preserve_generation(self):
        self.env["MULTI_USER"] = "1"
        self.import_ca()
        before = self.snapshot()
        first = self.certificates[1][0]
        result = self.policy("10:com.first.app " + first + " user", success=False)
        self.assertIn("Android user 10", result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.user_base / "10").exists())
        self.user_baseline(0, 0)
        self.policy("@global " + first + " user", success=False)
        self.assertEqual(self.snapshot(), before)
        self.user_baseline(10, 0)
        self.policy("10:com.first.app " + first + " both", success=False, FAIL_USER_CHCON="1")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.stops.read_text(), "")

    def test_invalid_user_mountpoint_preserves_policy_and_profile_data(self):
        self.env["MULTI_USER"] = "1"
        self.import_ca()
        self.user_baseline(0, 0)
        (self.user_base / "10").mkdir()
        target = self.user_base / "10/cacerts-added"
        target.symlink_to(self.user_base / "0/cacerts-added", target_is_directory=True)
        first = self.certificates[1][0]
        before = self.snapshot()
        self.policy("@global " + first + " user", success=False)
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(target.is_symlink())
        target.unlink()
        target.write_text("Existing profile data")
        self.policy("10:com.first.app " + first + " both", success=False)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(target.read_text(), "Existing profile data")

    def test_explicit_apply_reapplies_unchanged_global_mounts_and_rolls_back_on_failure(self):
        self.import_ca()
        first = self.certificates[1][0]
        self.policy("@global " + first, "com.first.app " + first + " off")
        self.global_calls.write_text("")
        self.run_manage("prepare")
        self.assertEqual(self.global_calls.read_text(), "", "Ordinary prepare must not force unchanged mounts")
        self.stops.write_text("")
        self.run_manage("apply")
        calls = self.global_calls.read_text().splitlines()
        self.assertEqual(calls, [str((self.runtime / "current/global").resolve())])
        self.assertEqual(self.status()["assignments"], {"com.first.app": {first: "off"}})
        self.assertEqual(self.stops.read_text().splitlines(), ["com.first.app"])
        before = self.snapshot()
        self.stops.write_text("")
        self.run_manage("apply", success=False, FAIL_GLOBAL="1")
        self.assertEqual(self.snapshot(), before)
        failed_calls = self.global_calls.read_text().splitlines()
        self.assertEqual(len(failed_calls), 3)
        self.assertEqual(failed_calls[-1], calls[-1], "Failed reapply must restore the previous global source")
        self.assertEqual(self.stops.read_text(), "")

    def test_global_mode_changes_are_published_even_when_certificate_name_is_same(self):
        self.import_ca()
        self.user_baseline(0, 0)
        first = self.certificates[1][0]
        self.policy("@global " + first)
        current = self.runtime / "current"
        self.assertTrue((current / "global/system-enabled").exists())
        self.policy("@global " + first + " user")
        self.assertFalse((current / "global/system-enabled").exists())
        self.assertEqual(len(self.global_calls.read_text().splitlines()), 2)
        self.assertEqual((self.state / "settings/global-certs").read_text(), first + " user\n")
        self.policy("@global " + first + " both")
        self.assertTrue((current / "global/system-enabled").exists())
        self.assertTrue((current / "global/user/0").exists())
        self.assertEqual(len(self.global_calls.read_text().splitlines()), 3)
        self.policy("@global " + first + " both")
        self.assertEqual(len(self.global_calls.read_text().splitlines()), 3)

    def test_merge_and_label_failures_preserve_generations(self):
        self.import_ca()
        before = self.snapshot()
        for failure in ("FAIL_MERGE", "FAIL_CHCON", "FAIL_PM"):
            with self.subTest(failure=failure):
                self.policy("com.first.app " + self.certificates[1][0], success=False, **{failure: "1"})
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.stops.read_text(), "")

    def test_failed_runtime_publication_rolls_settings_back(self):
        self.import_ca()
        self.policy("com.first.app " + self.certificates[1][0])
        before = self.snapshot()
        self.stops.write_text("")
        self.run_manage("remove-cert", self.certificates[1][0],
                        success=False, FAIL_PUBLISH="1")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.stops.read_text(), "")
        self.assertFalse((self.state / "settings.next").exists())
        self.assertFalse((self.runtime / "current.next").exists())

    def test_readiness_requires_a_live_snapshot_not_just_a_heartbeat(self):
        self.run_manage("prepare")
        (self.runtime / "zygisk64").write_text("1\n")
        self.assertTrue(self.status()["ready"])
        system = self.runtime / "current/global/system"
        system.rename(self.runtime / "missing-system")
        self.assertFalse(self.status()["ready"])
        (self.runtime / "current").unlink()
        (self.runtime / "current").symlink_to(self.runtime / "nonexistent")
        self.assertFalse(self.status()["ready"])

    def test_global_policy_still_requires_a_live_zygisk_callback(self):
        self.import_ca()
        self.policy("@global " + self.certificates[1][0])
        self.assertFalse(self.status()["ready"])
        (self.runtime / "zygisk64").write_text("1\n")
        self.assertTrue(self.status()["ready"])

    def test_pre_apex_store_and_legacy_global_mount_rejection(self):
        shutil.rmtree(self.apex)
        self.import_ca()
        self.assertFalse((self.runtime / "current/global/apex").exists())
        before = self.snapshot()
        (self.stock / ".trustusercerts").touch()
        self.run_manage("apply", success=False)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.status()["ready"])

    def test_two_independent_app_sets_add_global_without_cross_grants(self):
        for index in (1, 2, 3):
            self.import_ca(index)
        stock, first, second, globally = [cert[0] for cert in self.certificates]
        self.policy("com.first.app " + first, "com.second.app " + second, "@global " + globally)
        status = self.status()
        self.assertEqual(status["assignments"], {"com.first.app": {first: "system"}, "com.second.app": {second: "system"}})
        self.assertEqual(status["globalCertificates"], {globally: "system"})
        self.assertEqual((self.runtime / "current/config").read_text(),
                         "10001 com.first.app\n10002 com.second.app\n")
        for store in ("system", "apex"):
            self.assertEqual(self.ca_names(self.runtime / "current/global" / store), {stock, globally})
            self.assertEqual(self.ca_names(self.runtime / "current/apps/0/com.first.app" / store), {stock, first, globally})
            self.assertEqual(self.ca_names(self.runtime / "current/apps/0/com.second.app" / store), {stock, second, globally})
        self.assertEqual(len(self.global_calls.read_text().splitlines()), 1)
        self.assertTrue((self.runtime / "global.applied/enabled").is_file())
        self.policy("com.first.app " + first, "com.second.app " + second, "@global " + globally)
        self.assertEqual(len(self.global_calls.read_text().splitlines()), 1, "Unchanged global CA set must not remount")
        self.policy("com.first.app " + first, "com.second.app " + second)
        self.assertEqual(len(self.global_calls.read_text().splitlines()), 2)
        baseline = Path(self.global_calls.read_text().splitlines()[-1])
        self.assertFalse((baseline / "enabled").exists())
        self.assertEqual(self.ca_names(baseline / "system"), {stock})
        self.assertFalse((self.runtime / "global.applied").exists())

    def test_deleting_shared_global_ca_drops_all_references_and_import_stays_unassigned(self):
        self.import_ca(1)
        self.import_ca(2)
        stock, first, second, extra = [cert[0] for cert in self.certificates]
        self.policy("com.first.app " + first, "com.second.app " + second, "@global " + first)
        calls = self.global_calls.read_text()
        self.import_ca(3)
        self.assertEqual(self.global_calls.read_text(), calls)
        self.assertEqual(self.status()["globalCertificates"], {first: "system"})
        self.assertNotIn(extra, self.ca_names(self.runtime / "current/global/system"))
        self.stops.write_text("")
        self.run_manage("remove-cert", first)
        status = self.status()
        self.assertEqual(status["assignments"], {"com.second.app": {second: "system"}})
        self.assertEqual(status["globalCertificates"], {})
        self.assertEqual(self.ca_names(self.runtime / "current/apps/0/com.second.app/system"), {stock, second})
        self.assertEqual(self.stops.read_text().splitlines(), ["com.first.app", "com.second.app"])
        self.assertEqual(len(self.global_calls.read_text().splitlines()), 2)
        self.assertFalse((Path(self.global_calls.read_text().splitlines()[-1]) / "enabled").exists())

    def test_global_apply_and_publish_failures_restore_previous_policy_and_mount_source(self):
        self.import_ca(1)
        self.import_ca(2)
        first, second = self.certificates[1][0], self.certificates[2][0]
        self.policy("com.first.app " + first, "@global " + first)
        before = self.snapshot()
        previous_source = str((self.runtime / "global.applied").resolve())
        self.stops.write_text("")
        for failure in ("FAIL_GLOBAL", "FAIL_PUBLISH"):
            with self.subTest(failure=failure):
                prior_calls = len(self.global_calls.read_text().splitlines())
                self.policy("com.second.app " + second, "@global " + second,
                            success=False, **{failure: "1"})
                self.assertEqual(self.snapshot(), before)
                calls = self.global_calls.read_text().splitlines()
                self.assertEqual(len(calls), prior_calls + 2, "Failed update must apply rollback mounts")
                self.assertEqual(calls[-1], previous_source)
                self.assertEqual(self.stops.read_text(), "")

    def test_legacy_package_list_is_stopped_but_never_auto_granted(self):
        self.import_ca()
        settings = self.state / "settings"
        (settings / "packages").write_text("com.first.app\n")
        (settings / "rules").unlink()
        self.assertEqual(self.status()["assignments"], {})
        self.policy()
        self.assertEqual(self.status()["assignments"], {})
        self.assertEqual(self.status()["globalCertificates"], {})
        self.assertEqual((self.runtime / "current/config").read_text(), "")
        self.assertFalse((self.runtime / "current/apps/0/com.first.app").exists())
        self.assertEqual(self.stops.read_text().splitlines(), ["com.first.app"])
        self.assertEqual((self.state / "settings/packages").read_text(), "")

    def test_failed_post_commit_global_marker_keeps_live_store_and_next_apply_repairs_it(self):
        self.import_ca()
        first = self.certificates[1][0]
        self.policy("com.first.app " + first, "@global " + first,
                    success=False, FAIL_MARKER="1")
        self.assertTrue((self.runtime / "current/global/system").is_dir())
        self.assertTrue((self.runtime / "current/apps/0/com.first.app/system").is_dir())
        self.assertTrue((self.state / "settings/rules").is_file())
        self.assertEqual(self.status()["assignments"], {"com.first.app": {first: "system"}})
        self.assertEqual(self.status()["globalCertificates"], {first: "system"})
        self.assertFalse((self.runtime / "global.applied").exists())
        self.assertEqual(len(self.global_calls.read_text().splitlines()), 1)
        self.run_manage("apply")
        self.assertEqual((self.runtime / "global.applied").resolve(), (self.runtime / "current/global").resolve())
        self.assertEqual(len(self.global_calls.read_text().splitlines()), 2)
        self.assertEqual(self.stops.read_text().splitlines(), ["com.first.app"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
