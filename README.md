# Trust User Certs

This module injects all user certificates into system certificates.

This module targets Android 8.0+ with Magisk or KernelSU, including temporary root through DFRoot.

This module's main code logic comes from [HTTP Toolkit](https://github.com/httptoolkit/httptoolkit-server/blob/main/src/interceptors/android/adb-commands.ts)

### Installation
1. Install Magisk or obtain KernelSU root (for example through DFRoot)
2. Use the module ZIP built from this version (v1.3)
3. Install module through Magisk or KernelSU Manager
4. (Optional) create a **file** named /data/adb/trustusercerts/no_user_cert and put certificates into /data/adb/trustusercerts/certificates (You need to follow Android's system certificate naming rules, [ref](https://medium.com/hackers-secrets/adding-a-certificate-to-android-system-trust-store-ae8ca3519a85) - This step will make module using certificates from this folder instead of user certificates

### Adding certificates
Depending on have you done step 4 in installation, you need to install the certificate as a user certificate or put the certificate into /data/adb/trustusercerts/certificates

Then press the module's **Action** button to apply the changes. Restart the target app if it caches its TLS trust store.

### Removing certificates
Depending on have you done step 4 in installation, you need to remove the certificate as a user certificate or remove the certificate from /data/adb/trustusercerts/certificates

Then press the module's **Action** button and restart the target app to discard cached certificates.

### KernelSU late-load / DFRoot

Standard KernelSU runs `service.sh` in both normal boot and [late-load mode](https://kernelsu.org/guide/module.html#late-load-mode), so certificates are applied automatically when KernelSU activates and loads enabled modules. This module uses bind mounts backed by `/dev` (tmpfs); no metamodule is needed.

**diabl0w KernelSU (`samsung-v1.0`):** this fork [skips module activation and scripts during late-load](https://github.com/diabl0w/KernelSU/blob/samsung-v1.0/userspace/ksud/src/late_load.rs). Enable **Auto Soft Reboot** in DFRoot so that, after obtaining root, KernelSU performs its module initialization and starts the module. A soft reboot restarts Android services and apps while keeping the running kernel and root; save your work first. Renaming the Manager package does not change this behavior. Without module initialization, files remain in `modules_update` and the module cannot start itself.

For the **first installation or an update**, KernelSU stages files in `/data/adb/modules_update`. Apply the new version immediately from a root terminal, without rebooting:

```sh
su
KSU=true /data/adb/ksu/bin/busybox sh /data/adb/modules_update/trustusercerts/action.sh
```

After KernelSU activates the staged module (during standard late-load, or the required soft reboot in the diabl0w fork), use its **Action** button for subsequent certificate changes. If DFRoot has **Disable KSU Modules** enabled, automatic application is disabled.

A full reboot clears the certificate mounts and temporary root. Restore root through DFRoot to apply the module again. The module does not modify the system partition. Disable or uninstall it, then reboot without loading it to remove its mounts.

Logs: `/data/adb/trustusercerts/module.log`. Certificate pinning and apps with their own trust stores are outside this module's scope. Only Android user 0 is supported, as before.

Each Action keeps a small certificate snapshot in RAM until the next reboot. Restart apps after removing a certificate to discard cached trust decisions.

### Validation

The isolated test in `.github/tests/test-service.sh` runs as root on Android with KernelSU BusyBox. It uses temporary test stores and private mount namespaces, leaving the phone's actual trust stores alone:

```sh
/data/adb/ksu/bin/busybox sh .github/tests/test-service.sh "$PWD/service.sh"
```

It checks APEX and pre-APEX stores, existing app namespaces, repeated actions, certificate removal, the custom folder and setup failures. It does not test the DFRoot root-restoration sequence or app TLS connections.

### [Changelog](https://github.com/lupohan44/TrustUserCertificates/blob/main/changelog.md)
