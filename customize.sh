# Error on < Android 8.
if [ "$API" -lt 26 ]; then
    abort "- !!! You can't use this module on Android < 8.0"
fi

# create folder to add customized settings
if [ ! -d "/data/adb/trustusercerts" ]; then
	mkdir -p /data/adb/trustusercerts
fi

if [ ! -d "/data/adb/trustusercerts/certificates" ]; then
    mkdir -p /data/adb/trustusercerts/certificates
fi

ui_print "- Completed"
if [ "$KSU" = true ]; then
    ui_print "- For temporary root, apply now from a root shell:"
    ui_print "  KSU=true /data/adb/ksu/bin/busybox sh $MODPATH/action.sh"
    ui_print "- For diabl0w KernelSU, enable Auto Soft Reboot in DFRoot to activate modules."
    ui_print "- Once KernelSU activates this module, use its Action button to refresh certificates."
fi
ui_print "- If you want to add certificates without adding them into user certificates, please create a file named /data/adb/trustusercerts/no_user_cert and put certificates into /data/adb/trustusercerts/certificates"
