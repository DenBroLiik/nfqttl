#!/sbin/sh
ui_print "Nfqttl Eclipse 3.0.0 — speed + stability for stone"
APP_ABI=$(getprop ro.product.cpu.abi)
[ "$APP_ABI" = "arm64-v8a" ] || abort "This stone/Eclipse build is arm64-v8a only (got: $APP_ABI)"
[ -f "$MODPATH/libs/$APP_ABI/nfqttl-lite" ] || abort "Missing arm64 worker"
cp -f "$MODPATH/libs/$APP_ABI/nfqttl-lite" "$MODPATH/nfqttl-lite"
rm -rf "$MODPATH/libs"

# Preserve old user choices, then append new v3 options only when absent.
if [ -f /data/adb/modules/nfqttl/config.conf ]; then
    cp -f /data/adb/modules/nfqttl/config.conf "$MODPATH/config.conf"
    sed -i 's/^MAX_FAILURES=3$/MAX_FAILURES=6/; s/^COOLDOWN=15$/COOLDOWN=3/' "$MODPATH/config.conf"
    grep -q '^WORKERS=' "$MODPATH/config.conf" || echo 'WORKERS=4' >> "$MODPATH/config.conf"
    grep -q '^IPV6_MODE=' "$MODPATH/config.conf" || echo 'IPV6_MODE=auto' >> "$MODPATH/config.conf"
    grep -q '^IPV6_HL=' "$MODPATH/config.conf" || echo 'IPV6_HL=64' >> "$MODPATH/config.conf"
    grep -q '^MAX_BACKLOG=' "$MODPATH/config.conf" || echo 'MAX_BACKLOG=768' >> "$MODPATH/config.conf"
    grep -q '^STALL_LIMIT=' "$MODPATH/config.conf" || echo 'STALL_LIMIT=3' >> "$MODPATH/config.conf"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
for file in nfqttl-lite service.sh common.sh control.sh diagnose.sh uninstall.sh; do
    set_perm "$MODPATH/$file" 0 0 0755
done
ui_print "Eclipse/stone: GSO NFQUEUE + up to 4 balanced workers when native TTL is absent."
ui_print "IPv6: normalize HL when supported, otherwise auto blocks tether-forwarded IPv6 to avoid leaks."
ui_print "Reboot, restart hotspot, then test speed and call stability."
ui_print "Diagnostics: su -c 'sh /data/adb/modules/nfqttl/diagnose.sh during'"
