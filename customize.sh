#!/sbin/sh
ui_print "Nfqttl Eclipse Rust 4.0.0 — stone/RisingOS/Eclipse"
APP_ABI=$(getprop ro.product.cpu.abi)
[ "$APP_ABI" = "arm64-v8a" ] || abort "This build is arm64-v8a only (got: $APP_ABI)"
[ -f "$MODPATH/libs/$APP_ABI/nfqttl" ] || abort "Missing Rust arm64 binary. Build it first with src/build.sh."
cp -f "$MODPATH/libs/$APP_ABI/nfqttl" "$MODPATH/nfqttl"
rm -rf "$MODPATH/libs"

if [ -f /data/adb/modules/nfqttl/config.conf ]; then
    cp -f /data/adb/modules/nfqttl/config.conf "$MODPATH/config.conf"
    grep -q '^WORKERS=' "$MODPATH/config.conf" || echo 'WORKERS=4' >> "$MODPATH/config.conf"
    grep -q '^IPV6_MODE=' "$MODPATH/config.conf" || echo 'IPV6_MODE=auto' >> "$MODPATH/config.conf"
    grep -q '^IPV6_HL=' "$MODPATH/config.conf" || echo 'IPV6_HL=64' >> "$MODPATH/config.conf"
    grep -q '^MAX_BACKLOG=' "$MODPATH/config.conf" || echo 'MAX_BACKLOG=768' >> "$MODPATH/config.conf"
    grep -q '^STALL_LIMIT=' "$MODPATH/config.conf" || echo 'STALL_LIMIT=3' >> "$MODPATH/config.conf"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
for file in nfqttl service.sh control.sh diagnose.sh uninstall.sh; do
    set_perm "$MODPATH/$file" 0 0 0755
done
ui_print "Core logic is now Rust: daemon, CLI and raw-netlink NFQUEUE workers."
ui_print "Kernel TTL/HL backend is still preferred when Eclipse exposes xt_HL/TTL."
ui_print "Reboot and check: su -c '/data/adb/modules/nfqttl/nfqttl status'"
