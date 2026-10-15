# Trust User Certificates

Per-application System and User CA trust for Android 8.0+, maintained by lupohan44 and kiber.io. Requires Zygisk
API 4: Magisk 26+ with Zygisk enabled, or KernelSU with a compatible Zygisk Next,
ReZygisk or NeoZygisk installation. Configuration uses KernelSU's module WebUI.

Import CAs and choose which ones each application receives in the WebUI. Each
application receives its selected CAs as System, User or Both. An
optional global CA set applies to all supported apps. Each app can inherit a CA's
global mode, exclude it with Off, or replace its mode with System, User or Both. The global set is empty by
default. Existing Android user CAs are preserved; imports into the module's library
are explicit. The system partition is never modified.

The Material 3 WebUI opens on Overview, followed by Certificates and Apps.
Logs are collapsed by default. A save FAB appears only when the trust policy has
unsaved changes. App assignments are independent for each Android user and work profile.
It uses the manager's dynamic palette through KernelSU's local
`/internal/colors.css` when available, falling back to a standard light/dark theme
on managers without that feature. App icons are stored as local PNG assets so the
KernelSU command bridge only carries the compact app list.

## Install and configure

1. Install a Zygisk provider if using KernelSU, and activate it.
2. Install the **built** `TrustUserCertificates-v2.5.zip` in KernelSU.
   A ZIP of the repository source is not installable: it lacks compiled libraries
   and the certificate helper.
3. Activate the module, then open its **WebUI** in KernelSU.
4. Use **Add certificate** to select one PEM or DER CA certificate (up to
   64 KiB). Private keys, certificate bundles and non-CA certificates are rejected.
   Check the displayed subject and SHA-256 fingerprint against your trusted source.
5. Find applications by their real names or package identifiers, expand an app,
   choose Inherit, Off, System, User or Both for its certificates, and tap the save FAB.
   Inherit uses the global setting; Off excludes that module CA from the app.
   Original Android system and user CAs remain trusted. Individually configured apps sort first.
   Use the profile filter to select a personal, work or secondary-user copy of an app.
   To trust a CA everywhere, select it separately in the optional global section
   of the certificate tab and save that policy.
6. Open the affected applications again. Importing, deleting, saving and applying
   changes stop the previously selected and newly selected applications. Save
   their work first; the module does not automatically reopen them.

Importing a certificate alone never assigns it to any application or global set.
Deleting a certificate removes its assignments everywhere. Trusting a CA permits
all otherwise valid certificate chains from that CA, rather than a particular
website. Pinning and applications using their own trust stores can still reject
connections.

User mode overlays `/data/misc/user/USER_ID/cacerts-added` only in the target
process's private mount namespace, preserving that profile's original user CAs.
It does not install certificates through Android's certificate manager or change
the real user store. The app must allow user CA trust in its network security
configuration. System mode remains the default for existing assignments.

WebView can classify a CA found in the system store as a known system root and
apply additional certificate policies. User-only mode avoids this classification
only if the same trust anchor is absent from the app's system store. A per-app
User override also excludes that CA's global System injection. Both may still trigger those policies. Expiry, hostname and chain
signature checks remain in place.

Global System changes update Zygote and running app mount namespaces. They do not force
stop every application; restart affected apps to clear TLS caches, especially when
removing global trust. Individual applications affected by a policy change are
stopped and must be reopened manually.
Global User assignments apply when app processes start; restart affected apps.
User stores are never mounted into Zygote or a shared system namespace.

When upgrading from v2.0, certificate files remain in the library, but the old
shared app allowlist does not grant certificates in the new per-CA policy. Choose
the certificates explicitly for each app. No CA becomes global during an upgrade.

The WebUI reports whether this module has observed a callback from a currently
running Zygote. This is evidence that a Zygisk callback ran for at least one
architecture, not proof that a particular TLS connection used an imported CA.
Open an ordinary app and reopen/refresh the WebUI if no callback has appeared yet.
Per-process mount results are shown in the collapsed log on **Overview**.

## Upgrading from global injection

Version 1.x injects globally. Its mounts and applications' cached trust decisions
survive a module update. Install this version and **fully reboot** before testing
isolation. The new backend refuses to publish a selective store if it detects the
old global mounts. Old `no_user_cert` settings and certificate folders are not
imported; add your chosen certificates through the WebUI.
If this CA is also installed in Android's user certificate store, remove that
copy yourself before testing exclusive trust: apps that already accept user CAs
can otherwise continue trusting it. The module never deletes Android user CAs.

## Temporary root / DFRoot

Temporary root can provide the permissions needed by both modules, but the Zygisk
provider and this module must actually be activated. Merely staging a ZIP in
`/data/adb/modules_update` does not load its native code into new app processes.

The diabl0w KernelSU `samsung-v1.0` fork skips ordinary module initialization
during late-load. In that setup, DFRoot's **Auto Soft Reboot** can activate modules
after restoring root. A soft reboot restarts Android services and applications
while retaining the running kernel; save your work before using it. It does not
replace the full reboot needed to clear an old global injection installation.
NeoZygisk v2.4 also caches module libraries in its persistent daemon. A soft
reboot can restart Zygote while leaving that daemon's previous library cached.
After updating this module with NeoZygisk v2.4, fully reboot, restore temporary
root, and activate modules again to ensure the new native library is loaded.
Leave **Disable KSU Modules** off when intentionally loading these modules.

After a full reboot, restore root and activate modules again. Certificate settings
persist, while runtime stores are recreated. Exact compatibility of the installed
DFRoot, KernelSU and Zygisk versions needs testing on the device. The module does
not install, start or change your Zygisk provider itself.

References: [KernelSU WebUI](https://kernelsu.org/guide/module-webui.html),
[Zygisk Next](https://github.com/LSPosed/ZygiskNext),
[DFRoot](https://github.com/diabl0w/DFRoot),
[diabl0w late-load implementation](https://github.com/diabl0w/KernelSU/blob/samsung-v1.0/userspace/ksud/src/late_load.rs).

## Scope and diagnostics

Individual injection supports app IDs 10000–19999 in each Android user, including
work profiles and secondary users. Android's full UID identifies the selected copy.
Isolated processes (including some WebView/network workers),
SDK sandboxes, child Zygotes and system UIDs are excluded. Applications excluded
from Zygisk injection may lose globally selected certificates when Android rebuilds
their APEX namespace. Both modes require Zygisk for reliable per-process application.
Applications sharing an Android UID are not a security boundary. Optional global
injection also changes shared system trust namespaces, including Zygote and existing
app namespaces, so its effects can extend beyond the ordinary apps supported by
the native callback.

User-mode target directories must already exist for the selected Android user;
the module reports missing stores rather than creating or changing real user data.

Logs: `/data/adb/trustusercerts/module.log`, also visible in the WebUI. Failed
injections include the phase and errno. Settings
are root-only under `/data/adb/trustusercerts/settings`; this is a symlink to an
atomically published settings generation. Runtime snapshots and callback markers
live under `/dev/trustusercerts`. No global fallback occurs on an injection error.
Old snapshots remain in RAM until reboot, since existing processes can still be
using them. Restart affected apps after an injection failure; a timed-out kernel
mount operation can finish later in that app's private namespace.

Disabling or uninstalling prevents future injection after Zygisk reload; existing
processes can retain mounts and cached trust decisions. Fully reboot without
loading the module to remove them.

## Build and checks

In a WSL Ubuntu shell with an existing JDK 17+, Android SDK platform 35, build-tools 35.0.0 and
NDK 29.0.13113456, set `JAVA_HOME`, `ANDROID_HOME` and `ANDROID_NDK_HOME`, then run:

```sh
bash tools/build.sh
```

The installable ZIP appears under `.artifacts/`, with native libraries for arm64,
ARM32, x86-64 and x86. No JavaScript package installation is needed.

Host checks (Java, OpenSSL, Node, Python and a C++ compiler):

```sh
bash .github/tests/test-certificates.sh
node tests/webui.test.js
python3 .github/tests/test-manage.py
c++ -std=c++17 native/protocol_test.cpp -o /tmp/tuc-protocol-test
/tmp/tuc-protocol-test
bash -c 'exec -a zygote64 /tmp/tuc-protocol-test --zygote-name-check'
```

The certificate check covers strict parsing, CA constraints, legacy subject hashes,
duplicates, collisions and JSON output. WebUI checks use a mocked KernelSU bridge.
Backend checks execute the actual script with mocked Android services and verify
publication rollback and preservation of certificates on setup failures.

These host checks do not exercise Android SELinux, actual app mount namespaces or TLS.
The native device harness separately checks the readiness handshake and snapshot
mounting in a private child namespace under a supplied app SELinux context. The
device script `.github/tests/test-global.sh` checks global mount replacement,
removal and isolation using temporary paths. Neither verifies an app's TLS connection.
On a device, verify a selected app can connect through the imported CA while a
separate unselected app using Android's system trust cannot, then remove the CA,
reopen both apps and check again. Account for apps that already trust this CA,
use their own verifier or delegate networking to excluded processes.

See [native/README.md](native/README.md) for the Zygisk protocol and mount lifecycle.
