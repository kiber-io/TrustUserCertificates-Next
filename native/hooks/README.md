The optional `tuc-hooks` library is loaded only for an effective app policy with
nonzero hook flags. Its C entry point is:

    int tuc_hooks_prepare(JNIEnv *);
    int tuc_hooks_install(JNIEnv *, const void *dex, size_t dex_size, uint8_t flags);

Call `prepare` only in the selected zygote child before specialization. It
initializes ART native hooks and caches framework DexFile fields with unrestricted
JNI; it does not load HookBridge or initialize UserCertificateSource.

Flags are 1 (disable Certificate Transparency), 2 (add Android's user CA
source), and 4 (add Android's system CA source). The return value is the subset installed. Invoke this after final UID
specialization and successful certificate mounts, before application binding.
Installation requires successful preparation; there is no post-specialization
initialization fallback. No Java code is run by loading the library itself. The implementation copies the
payload bytes and keeps its Java loader alive, so the caller can release its dex
mapping after the call. Keep the library loaded after any preparation or installation attempt:
LSPlant initialization may have installed ART callbacks even if a later step
fails.

The trusted in-memory dex supplies `HookBridge`. It modifies the framework
NetworkSecurityConfig Builder before its original build method. LSPlant hooks
that method, and deoptimizes the default config constructor, XML parser and its
initialization wrapper to
avoid their precompiled inlined copies. Unknown OEM callers that inline the
method require separate compatibility verification. Apps using native TLS,
custom trust managers or their own CT implementation are outside this hook.
Hostname, certificate lifetime, signature checking and pinning remain active.

Build with `tools/build-hooks.sh`, NDK 29, CMake 3.31 and Ninja >=1.11. The library
statically links libc++ and the vendored LSPlant/DexBuilder/Dobby sources; see
`../vendor/README.md` for exact revisions and licenses. The ART resolver supports both ordinary ELF tables and Android release builds'
XZ-compressed mini ELF. It bounds decoding and releases symbol-file buffers once
initialization completes. Four Android ABIs are built. Each ABI keeps its raw
`libtuc-hooks.so` for debugging and stages a stripped distributable copy under
`package/libtuc-hooks.so`. The mounted CA feature itself does not depend on the hook engine.
