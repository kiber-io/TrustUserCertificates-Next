# Error on < Android 8.
if [ "$API" -lt 26 ]; then
    abort "- !!! You can't use this module on Android < 8.0"
fi

[ -f "$MODPATH/cert-tool.jar" ] || abort '- Missing certificate helper: install the built module ZIP'
case "$ARCH" in
    arm64) ZYGISK_ABI=arm64-v8a ;;
    arm) ZYGISK_ABI=armeabi-v7a ;;
    x64) ZYGISK_ABI=x86_64 ;;
    x86) ZYGISK_ABI=x86 ;;
    *) abort '- Unsupported architecture' ;;
esac
[ -f "$MODPATH/zygisk/$ZYGISK_ABI.so" ] || abort '- Missing Zygisk library for this architecture'
ui_print '- Selective trust requires Zygisk (Zygisk Next, ReZygisk or NeoZygisk on KernelSU).'
ui_print '- Open module WebUI to import a CA and select applications.'
ui_print '- No applications are selected by default. User certificates are not imported.'
ui_print '- After upgrading from global injection: fully reboot before testing isolation.'
ui_print '- DFRoot: restore root and activate modules; a soft reboot may be required.'
ui_print '- NeoZygisk updates: fully reboot, then restore DFRoot root to reload native libraries.'
ui_print '- Applying changes stops selected applications; save your work first.'
