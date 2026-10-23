# TUC Hook Probe

Package: `io.kiber.tuc.probe`. A separate diagnostic APK; not part of the installed module.

The manifest uses a real Network Security Config with only a bundled public test CA,
no system/user sources, and explicitly enabled CT on Android 16+. The test CA is not
installed into Android and its private key is not retained. There is no debug trust
override. The native reader only inspects this app's actual platform config; it has
no hook engine, root access, config setters or alternate trust manager.

Build in WSL/Linux using the same JDK 17, NDK 29 and build-tools 35 environment as
the module, plus SDK platform 36:

```sh
bash tests/hook-probe/build.sh
```

Output: `.artifacts/tuc-hook-probe.apk`. The debug signing key stays under the ignored
`.artifacts/hook-probe` directory; retain it to update an existing test installation.

Install, select **TUC Hook Probe** in the module WebUI, set hooks and save. Reopen
the APK after every change. Refresh rereads the existing process config; it cannot
reload Zygisk hooks. Android users and work profiles are separate module selections.

| Switch | Expected change |
| --- | --- |
| None | CT REQUIRED on Android 16+, System ABSENT, User ABSENT, Embedded ENABLED (1 CA). |
| Disable CT | CT DISABLED. |
| Trust system CAs | System ENABLED; existing embedded CA remains. |
| Trust user CAs | User ENABLED; its count may be zero in an empty profile. |

All eight combinations are valid. On older Android, CT reads UNSUPPORTED.
The CA counts describe source contents, not unique anchors across sources. Reading
sources verifies configuration, not a full TLS handshake or pin enforcement.

**Test HTTPS** uses ordinary `HttpsURLConnection`, with the app's original trust
manager, hostname validation and CT settings. No requests run automatically; enter
your test server URL and press the button. Without hooks, a public server normally
fails trust because the app trusts only its bundled CA. With system trust and CT
disabled, a correctly configured public server should connect. With CT required,
the result also depends on that server's SCTs, Android's CT logs and network access.
For a proxy test, inject its CA into this app's User or System store and enable the
matching trust switch; **Trust user CAs** alone does not import a CA.

Copy report copies the config result. ADB automation can read the same result as
root at `/data/user/USER_ID/io.kiber.tuc.probe/files/report.txt` or through logcat tag
`TucHookProbe`. Private APIs may differ on OEM builds; failures are shown as errors,
not as successful hook results.

After configuring the switches in WebUI, a rooted device can check the report:

```sh
bash tests/hook-probe/check-device.sh DEVICE_SERIAL EXPECTED_FLAGS [ANDROID_USER_ID]
```

Flags sum CT=1, User=2 and System=4. Use 0 for the baseline or 7 for all enabled.
This stops and relaunches only the probe; it does not change module policy.

This real XML configuration is also a regression test for compiled framework
callers: an installed Builder hook can report active while an inlined call in
`XmlConfigSource.parseNetworkSecurityConfig` bypasses it. Testing a fresh Builder
directly does not cover this path. The report must change after a process restart.
