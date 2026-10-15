# v2.5.1

* Make Action and WebUI Reapply restore global mounts even when the saved policy is unchanged.

# v2.5

* Rename the module to TUC Next and release archives to tuc-next, keeping the existing module ID and settings.
* Override global certificate modes per app and profile with Inherit, Off, System, User or Both.
* Keep the save notice visible so editing assignments does not move the app list.

# v2.4.1

* Replace native Android select dialogs with themed Material 3 menus for CA modes and profiles.

# v2.4

* Choose System, User or Both for each per-app or global certificate assignment.
* Merge original per-profile user CAs into private process mounts without modifying Android's user store.
* Keep user-only CAs out of injected system stores; applications must support user CA trust.

# v2.3.1

* Load app icons from local PNG files instead of embedding them in the KernelSU exec reply, avoiding timeouts with multiple profiles.

# v2.3

* Add independent app assignments for work profiles and secondary Android users.
* Simplify the WebUI: Overview first, collapsed logs, no persistent header/status chip.
* Save policy changes with a floating button shown only while edits are pending.
* Credit both lupohan44 and kiber.io; remove the experimental version suffix.

# v2.1-experimental.1

* Show progress inside the pressed button and paint it before invoking the root bridge.
* Wrap long certificate subjects and fingerprints within selection rows.
* Translate the WebUI and module status messages to English; replace the native file control with an import button.
* Reapply global CAs after app specialization restores the Conscrypt APEX namespace.

# v2.1-experimental

* Choose individual CA sets per application and an optional separate global CA set.
* Show real app labels/icons, sort individually configured apps first, and animate pending actions.
* Fix post-specialization SELinux failures without weakening policy: use a Zygote-created
  readiness pipe and a pre-mapped shared result page.
* Resolve mount sources within the destination namespace and verify their inode/device.
* Preserve original CA baselines when changing/removing global trust.
* Certificate files are retained on upgrade; assign them explicitly using the new per-CA policy.

# v2.0-experimental.2

* Redesign KernelSU WebUI with Material 3 bottom navigation and three tabs.
* Use KernelSU's local dynamic palette when available, with light/dark fallbacks.
* Fix Binder failures when stopping applications: do not pass a root-only settings
  file as Android `am` standard input.
* Log rejected companion handshakes and explain NeoZygisk's cached library status.

# v2.0-experimental.1

* Fix companion authentication when Android names the Zygote thread `main`.
  Identify Zygote from argv[0] instead, retaining sender UID and PID checks.

# v2.0-experimental

* Replace global injection with per-application system CA mounts through Zygisk.
* Add KernelSU WebUI for package selection, PEM/DER CA import, deletion and diagnostics.
* Leave all applications unselected by default; do not import Android user certificates.
* Validate CA files and preserve stock certificates when subject hashes collide.
* Apply changes by stopping affected applications; open them again manually.
* Experimental: device validation of provider compatibility, namespaces, SELinux and TLS is required.
* Upgrading from global injection requires a full reboot before verifying isolation.

# v1.3

* Support KernelSU late-load and temporary root through DFRoot.
* Add an Action button to apply certificate changes without rebooting.
* Fix BusyBox mount commands and injection into already running app namespaces.
* Preserve stock certificates across repeated actions and stop on setup errors.
* Write logs to /data/adb/trustusercerts/module.log.

# v1.2

* Change module description
* Support add certificate into folder /data/adb/trustusercerts/certificates instead of have to install as user certificate
* Change module log into magisk console

# v1.1

Fix wrong update url in module.prop

# v1.0

Initial Release
