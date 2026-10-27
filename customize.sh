#!/sbin/sh
ui_print "Nfqttl Eclipse 4.3 — stone / RisingOS"
APP_ABI=$(getprop ro.product.cpu.abi)
[ "$APP_ABI" = "arm64-v8a" ] || abort "This build requires arm64-v8a (got: $APP_ABI)"
[ -f "$MODPATH/libs/$APP_ABI/nfqttl" ] || abort "Missing ARM64 binary"
cp -f "$MODPATH/libs/$APP_ABI/nfqttl" "$MODPATH/nfqttl" || abort "Cannot install binary"
rm -rf "$MODPATH/libs"
# Read defaults from this release instead of maintaining a second settings list.
cp -f "$MODPATH/config.conf" "$MODPATH/config.defaults.conf" || abort "Cannot save defaults"
OLD=/data/adb/modules/nfqttl/config.conf
if [ -f "$OLD" ]; then
    cp -f "$OLD" "$MODPATH/config.conf" || abort "Cannot preserve configuration"
    while IFS= read -r line; do
        case "$line" in ''|'#'*) continue ;; esac
        key=${line%%=*}
        grep -q "^[[:space:]]*$key[[:space:]]*=" "$MODPATH/config.conf" || printf '%s\n' "$line" >> "$MODPATH/config.conf"
    done < "$MODPATH/config.defaults.conf"
fi
set_perm_recursive "$MODPATH" 0 0 0755 0644
for file in nfqttl service.sh action.sh control.sh diagnose.sh uninstall.sh; do
    set_perm "$MODPATH/$file" 0 0 0755
done
set_perm "$MODPATH/config.conf" 0 0 0600
"$MODPATH/nfqttl" check --module-dir "$MODPATH" || abort "Invalid config.conf; check duplicate/unknown keys and ranges. Previous installed configuration is unchanged."
ui_print "Existing settings preserved. Kernel TTL/HL is preferred; NFQUEUE is fallback."
ui_print "KernelSU: open WebUI, or use Action to pause/start."
ui_print "Reboot; restart hotspot if it was active."
ui_print "su -c '/data/adb/modules/nfqttl/nfqttl doctor'"
