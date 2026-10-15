# Selective certificate mounts

`module.cpp` uses Zygisk API 4. The unmodified public header comes from
[topjohnwu/zygisk-module-sample, commit 7bb941a](https://github.com/topjohnwu/zygisk-module-sample/blob/7bb941ac8edfcffd1d23761e401c45ca95409dc1/module/jni/zygisk.hpp)
and retains its upstream license.

Build with the Android NDK:

```sh
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=native/Android.mk \
  NDK_APPLICATION_MK=native/Application.mk \
  NDK_OUT=.artifacts/native/obj NDK_LIBS_OUT=.artifacts/native/libs
```

Package each `.artifacts/native/libs/ABI/libtrustusercerts.so` as
`zygisk/ABI.so`. There is no C++ runtime dependency.

The backend atomically publishes `/dev/trustusercerts/current`, a symlink to
an immutable snapshot containing `config` and `apps/USER_ID/PACKAGE/system/` with
optional `apps/USER_ID/PACKAGE/apex/` for every selected package. `config` contains
newline-separated `FULL_UID PACKAGE` records. The full Android UID is
`USER_ID * 100000 + APP_ID`; each user directory is a canonical decimal ID,
including `apps/0/PACKAGE` for the primary user. Each pair of directories contains
the corresponding original system trust store plus certificates selected with
the System bit. An effective snapshot can also contain `user/USER_ID`: the
original user-installed certificates for that user plus certificates selected
with the User bit. Both selects both bits. User directories and files must carry
their actual `misc_user_data_file:s0` SELinux label; system/APEX stores keep their
system labels. The native module does not relabel files or modify SELinux policy.
When global CAs are enabled, `global/enabled` is a zero-byte regular file and
`global/{system,apex}` contains their merged trust stores. An ordinary app without
an explicit package entry uses that global snapshot; explicit entries retain
their per-package union. This reapplies APEX mounts after specialization, which
can replace the mount inherited from Zygote.
When a `user/USER_ID` source exists, the worker also binds it read-only onto
`/data/misc/user/USER_ID/cacerts-added` inside that app's private namespace.
Missing user sources leave the original user store untouched. A supplied user
source with a missing target fails with `user-target`; the module never creates
real user-store directories, mounts them into Zygote, or changes original files.
All applied stores are rolled back on ordinary source/bind/remount errors,
including when the optional APEX store is absent.
Snapshot directories and config must remain root-owned and unwritable by apps.
Accepted data paths are `/data/user/USER_ID/PACKAGE` and
`/data/user_de/USER_ID/PACKAGE`; `/data/data/PACKAGE` is accepted only for user 0.
A path for a different user never identifies the requested app. Assignment keys
outside this native protocol use plain `PACKAGE` for user 0 and `USER_ID:PACKAGE`
for other users; native requests and config always carry the plain package plus
its full UID.

For ordinary apps in any Android user or work profile (APP_ID 10000–19999),
the module extracts the package from `app_data_dir`, verifies its user against
the full UID, connects to the root companion, and checks the selected
UID/package against the pinned snapshot. It unshares the app mount namespace
before specialization. The initial socket request authenticates the sender's
kernel-provided PID/UID and transfers a readiness pipe and a sealed-size memfd created by Zygote.
The module closes the socket before specialization: Android can deny app-domain
socket writes to the root companion. After specialization, it signals readiness
through the private pipe. The companion checks the UID and parent through a
pinned `/proc/PID` directory, avoiding numeric PID reuse. The app waits for an
atomic acknowledgement in the memfd page mapped read-only before specialization;
it needs no post-specialization socket write or pipe read. App-domain SELinux
policy permits writing a Zygote FIFO but can deny reading one. No global SELinux
policy changes are needed.
A short-lived worker enters the app's final mount namespace, refuses the Zygote
namespace, makes propagation private, and binds the CA directories read-only. Before binding,
it resolves each pinned source's immutable path in the destination namespace and
checks its device/inode: binding an inherited foreign-namespace O_PATH reference
can fail with EINVAL.
It acknowledges completion before normal app code starts. No Zygote mounts are
modified. IPC has a three-second timeout and worker completion a two-second limit.

The companion writes `/dev/trustusercerts/zygisk32` or `zygisk64` with the parent
Zygote PID after observing an ordinary-app callback. This proves an observed
callback for that Zygote, rather than just an installed provider. Selected-app
injection outcomes go to `/data/adb/trustusercerts/module.log`, including the exact
failure phase and errno. Client and companion must use the same build; restart
the provider normally after installing an update rather than hot-mixing cached
libraries with a different IPC protocol.

The host-portable selection check can be run with an existing C++ compiler:

```sh
c++ -std=c++17 native/protocol_test.cpp -o /tmp/trustusercerts-protocol-test
/tmp/trustusercerts-protocol-test
```

Device verification is still required for the installed provider, Android mount
setup, SELinux policy, and CA labels. Isolated processes, SDK sandboxes,
child Zygotes, and non-app UIDs are deliberately excluded. Shared UID
packages are not a security boundary. Processes must restart after a config or
CA change. Native TLS libraries with their own trust store and certificate
pinning can ignore these CA mounts. The global fallback covers only eligible
processes where Zygisk invokes this module; it does not guarantee global APEX
trust for excluded process types. An invalid explicit snapshot fails instead of
falling back to global stores. Ordinary mount failures roll back any already-applied
bind mounts. A kernel-stuck
mount or process termination during a multi-directory update can leave partial
mounts in that one app process, so restart it after an injection failure. A worker
that exceeds the timeout is not signalled by numeric PID, because provider child
reaping could recycle that PID; a kernel-stuck worker may finish later.

User mode only supplies a genuine user trust store; it does not make an app opt
into trusting that store. Apps targeting API 24+ must normally explicitly trust
user CAs in their [network security configuration](https://developer.android.com/privacy-and-security/security-config).
Android reads this store through [UserCertificateSource](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/security/net/config/UserCertificateSource.java).
Both, a stock system root, or an independent global System assignment can still
make Chromium classify the same subject/public key as a known system root, so
Both does not promise to avoid system-root certificate validity restrictions.
The user snapshot preserves existing user certificates at preparation time;
refresh the module and restart the app after OS user-store changes.

The native build also produces `trustusercerts-diagnostic` for a controlled device
check using the same pipe, credential, identity, and mount helpers. As root:

```sh
trustusercerts-diagnostic PACKAGE UID FIXTURE_SNAPSHOT [APP_SELINUX_CONTEXT]
```

The fixture contains `config` and `apps/USER_ID/PACKAGE/{system,apex}`, or an empty config
with `global/enabled` and `global/{system,apex}` to check the global fallback.
Add `user/USER_ID` under the effective snapshot to check the third store.
Create test mount targets `/dev/trustusercerts-check/{system,apex,user}` with
root ownership and mode 755. System/APEX targets and sources use `system_file`;
the user source and target use `misc_user_data_file`. Omit the user source to
check system-only behavior, or omit the user target to check safe failure.
The executable uses those test targets in a private
child namespace; it never mounts over the real trust stores or updates runtime
policy. With the final optional argument, its child enters the Zygote SELinux
domain before creating the pipes, then drops UID and enters the specified app
context before testing readiness and shared-memory acknowledgement. Supply the actual app's context.
The check reports whether a pre-existing socket can still send under its test
setup, verifies the requested app context through the pinned process directory,
then confirms readiness FIFO writing, shared-page acknowledgement, the snapshot
directory inodes, and that the parent's namespace remains unchanged. A root-launched
helper can retain root-manager task state, so it cannot fully reproduce every
restriction of an actual Zygote-created app. Root permission to change this helper's own SELinux
context is required for the optional domain transition check.
