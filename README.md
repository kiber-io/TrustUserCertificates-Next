# TUC Next

**TUC Next** is a fork of [Trust User Certificates](https://github.com/lupohan44/TrustUserCertificates)
by lupohan44, modified and maintained by kiber.io. It lets you choose which imported CA certificates Android
apps receive, either individually or through an optional global policy.

Supports Android 8.0+ and requires Zygisk API 4: Magisk 26+ with Zygisk enabled,
or KernelSU with a compatible Zygisk Next, ReZygisk or NeoZygisk installation.
Configuration uses KernelSU's module WebUI.

The module keeps its internal ID, `trustusercerts`, so TUC Next updates the existing
installation and retains its saved certificate library and policy. It does not
modify the system partition or install certificates into Android's real user store.

## Certificate modes

Import a CA into the module's library, then assign it globally or to a particular
app. Importing alone grants no trust. The global policy is empty by default.

| Mode | Effect for the selected app and profile |
| --- | --- |
| Inherit | Use this CA's global setting. If it has no global assignment, inject nothing. |
| Off | Exclude this CA from the module's injection for this app, even when enabled globally. |
| System | Expose this CA through the app's system certificate stores. |
| User | Expose this CA through the profile's user certificate store in the app's private namespace. |
| Both | Expose this CA through both stores. |

Each explicit app setting **replaces** that CA's global mode. For example, a global
System CA can be User-only in Talk, or Off in another app. Inherit restores the
global behavior. Global assignments offer Off, System, User and Both; Inherit is
only an app setting.

Off only excludes the module's copy. It does not remove an existing Android CA or
override an app's own trust store. Original Android system and user CAs are preserved.
The same package in a personal profile, work profile or secondary user has independent
assignments; use the profile filter to select the intended copy.

## WebUI

The Material 3 interface has three tabs:

* **Overview**: module status, Reapply and collapsed diagnostic logs.
* **Certificates**: import or delete CAs and configure global trust.
* **Apps**: search by app name or package, filter profiles and configure per-app modes.

Individually configured apps sort first, including apps with explicit Off rules.
A floating Save button appears only while policy edits are pending. The interface
uses KernelSU's dynamic palette when available, with light/dark fallbacks.

## Optional app hooks

A standalone [TUC Hook Probe APK](tests/hook-probe/README.md) can show the actual
CT policy and CA sources in a test app that initially excludes system/user CAs.
It also provides a manual HTTPS check and a copyable config report.

Expand an app in **Apps** to enable these options independently, then save:

| Option | Effect |
| --- | --- |
| Disable CT | Disable Android Network Security Configuration's Certificate Transparency requirement for this app. CT controls are available on Android 16+. |
| Trust system CAs | Add Android's system CA source even if the app excludes it, including CAs privately injected in System mode. |
| Trust user CAs | Add the selected profile's Android user CA source to the app's network security configuration, including CAs privately injected in User mode. |

All options are off by default and independent for each profile. They work without
editing or re-signing the APK, and can be saved even with an empty module certificate
library. Trust user CAs also permits CAs already installed in that profile's Android
user store; it does not automatically assign CAs from the module library.

The trust hook preserves the app's existing system and embedded CA sources and
certificate pins. It does not accept arbitrary certificates or disable expiry,
signature or hostname checks. Android normally exempts user CA sources from implicit
CT requirements; explicitly required CT remains enabled unless Disable CT is selected.
Disabling CT removes the requirement for evidence of public certificate logging.

These hooks affect Android's network security configuration. Apps with independent
trust managers, native TLS implementations, Chromium/WebView or Cronet can enforce
their own policies. An enabled switch is not proof that every connection uses the
platform verifier; check the process hook result in Diagnostics.

The engine also deoptimizes Android's compiled XML configuration parser, so
inlined Builder calls cannot silently bypass the hook. On a Pixel 7 running
Android 16, the probe's real XML config was verified with all three hooks enabled:
CT disabled, system/user sources added, and the embedded CA preserved. An HTTPS
request then completed with HTTP 200. Android 17 and other OEM builds still need
device verification; this check does not independently prove proxy capture.

The optional ART hook engine is loaded only in selected app processes and remains
there while they run. Apps without hooks keep the existing mount-only path. This
feature changes native libraries: fully reboot after installing the update, then
restore temporary root if applicable, so the Zygisk provider loads the new code.

## Install and configure

1. Install a Zygisk provider if using KernelSU, and activate it.
2. Install the **built** `tuc-next-v2.6.zip` in KernelSU.
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

## How injection works

The backend builds certificate snapshots from the original Android stores and the
saved policy. Zygisk selects the snapshot for the app's full Android UID and package
and mounts it in that process's private mount namespace. An app with an explicit
Off rule still receives a snapshot so the module can exclude a globally injected CA.

System mode overlays the system CA directory and the Conscrypt APEX CA directory
where present. User mode overlays `/data/misc/user/USER_ID/cacerts-added` only in the target
process's private mount namespace, preserving that profile's original user CAs.
It does not install certificates through Android's certificate manager or change
the real user store. The app must allow user CA trust in its network security
configuration. System mode remains the default for existing assignments.

WebView can classify a CA found in the system store as a known system root and
apply additional certificate policies. User-only mode avoids this classification
only if the same trust anchor is absent from the app's system store. A per-app
User override also excludes that CA's global System injection. Both may still
trigger those policies. Expiry, hostname and chain signature checks remain in place.

Global System changes update Zygote and running app mount namespaces. They do not force
stop every application; restart affected apps to clear TLS caches, especially when
removing global trust. Individual applications affected by a policy change are
stopped and must be reopened manually.
Global User assignments apply when app processes start; restart affected apps.
User stores are never mounted into Zygote or a shared system namespace.

**Reapply** on Overview and the manager's **Action** button both reapply the saved
policy and stop configured apps. They do not save pending WebUI edits or reopen apps.
Explicit reapplication restores global System mounts even when the policy is unchanged.
Saving assignments normally needs no device reboot: reopen the stopped apps.
After a WebUI-only update, close and reopen the WebUI.

## Updates and temporary root

When upgrading from v2.0, certificate files remain in the library, but the old
shared app allowlist does not grant certificates in the new per-CA policy. Choose
the certificates explicitly for each app. No CA becomes global during an upgrade.

The WebUI reports whether this module has observed a callback from a currently
running Zygote. This is evidence that a Zygisk callback ran for at least one
architecture, not proof that a particular TLS connection used an imported CA.
Open an ordinary app and reopen/refresh the WebUI if no callback has appeared yet.
Per-process mount results are shown in the collapsed log on **Overview**.

### Upgrading from global injection

Version 1.x injects globally. Its mounts and applications' cached trust decisions
survive a module update. Install this version and **fully reboot** before testing
isolation. The new backend refuses to publish a selective store if it detects the
old global mounts. Old `no_user_cert` settings and certificate folders are not
imported; add your chosen certificates through the WebUI.
If this CA is also installed in Android's user certificate store, remove that
copy yourself before testing exclusive trust: apps that already accept user CAs
can otherwise continue trusting it. The module never deletes Android user CAs.

### Temporary root / DFRoot

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
After an update that changes this module's native Zygisk libraries with NeoZygisk
v2.4, fully reboot, restore temporary root, and activate modules again to ensure
the new native library is loaded. Changes limited to the WebUI or scripts do not
require reloading those libraries.
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
their APEX namespace. System and User injection both require Zygisk for reliable
per-process application.
Applications sharing an Android UID are not a security boundary. Optional global
injection also changes shared system trust namespaces, including Zygote and existing
app namespaces, so its effects can extend beyond the ordinary apps supported by
the native callback.

If an existing Android profile has no `cacerts-added` directory, the module creates
an empty mount point with that profile's system ownership and Android SELinux label.
It never writes imported CA files there. Failed updates remove newly created empty
mount points; existing stores and their certificates are preserved. Missing profile
data directories, invalid paths and permission failures still abort the update.

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

In a WSL Ubuntu shell with an existing JDK 17+, Android SDK platform 35, build-tools
35.0.0, NDK 29.0.13113456, SDK CMake 3.31.0 and Ninja 1.11+, set `JAVA_HOME`,
`ANDROID_HOME` and `ANDROID_NDK_HOME`, then run:

```sh
bash tools/build.sh
```

The installable `tuc-next-VERSION.zip` and matching `tuc-next-VERSION-source.zip`
appear under `.artifacts/`. The source archive includes the code, build scripts
and build instructions. The installable ZIP includes native libraries for arm64,
ARM32, x86-64 and x86. No JavaScript package installation is needed.

Host checks (Java, OpenSSL, Node, Python and a C++ compiler):

```sh
bash .github/tests/test-certificates.sh
bash .github/tests/test-hooks.sh
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

## License and source

TUC Next is distributed under the **GNU Affero General Public License, version 3**
([LICENSE](LICENSE)), without warranty. You may redistribute and modify it under
that license. Original author: lupohan44. Fork modifications: kiber.io,
2026-10-15, including selective and global CA policies, System/User modes,
multi-profile support, Zygisk integration and the WebUI.

Source: [kiber-io/TrustUserCertificates-Next](https://github.com/kiber-io/TrustUserCertificates-Next).
Each binary release must be accompanied by its matching `tuc-next-VERSION-source.zip`
at the same release download location, at no additional charge. Publish the code
used to build the release; a link to an unrelated or older revision is insufficient.

See [NOTICE](NOTICE) for attribution and the separate licenses of the Zygisk API
header and ART hook dependencies. Their full source is included in the source
archive, and their license texts are included in the installable archive.
The original project's README also credits
[HTTP Toolkit](https://httptoolkit.com/blog/android-14-install-system-ca-certificate/)
for its main certificate injection logic.
