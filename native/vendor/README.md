Pinned native dependencies for the optional ART hook engine:

- LSPlant d8b5d1dbb664abc606644036822e4bb64547edf6, https://github.com/LSPosed/LSPlant, LGPL-3.0.
- DexBuilder ac7fb2230954ee311808bad469b0db501f31bfb8, https://github.com/LSPosed/DexBuilder, LGPL-3.0.
- parallel-hashmap 0cd57d29a959256ed66b2afdd1009928fc625d09, https://github.com/greg7mdp/parallel-hashmap, Apache-2.0 (see its license for included components).
- XZ Embedded ae63ae3a36ed01724674e8f3d750dc47bf125410, https://github.com/tukaani-project/xz-embedded, 0BSD (COPYING).
- Dobby e9fe7fbecae47a2287e761080f8b1133cc22e8fa, https://github.com/jmpews/Dobby, Apache-2.0.

Each dependency retains its original license and source. LSPlant is pinned to the
Android 17 GSI fix immediately before the upstream NDK 30 standard-library-module
build migration, so it builds with this project's NDK 29 and CMake 3.31.

Local Dobby changes: mark Logger::Shared
inline to fix its header definition when statically linked; enumerate loaded ELF
images with dl_iterate_phdr instead of dereferencing arbitrary process mappings
(the latter caused a reproduced SIGBUS in ART app_process testing). Dobby uses its stable
pre-refactor Linux backend rather than the latest tag with stale Linux sources.

The project ART resolver also decodes XZ-compressed .gnu_debugdata for release
Android builds. It caches decoding during initialization and releases file buffers
after LSPlant initialization. Mini-ELF symbol tables may be unaligned; records are
copied before access so ARMv7 works as well.
