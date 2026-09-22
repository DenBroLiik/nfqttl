#!/system/bin/sh
MODDIR=${0%/*}
umask 077
LABEL=${1:-snapshot}
case "$LABEL" in *[!a-zA-Z0-9_-]*|'') echo "Use a simple label: before, during, after"; exit 2;; esac
OUT=/sdcard/Download/nfqttl_$(date +%Y%m%d_%H%M%S)_${LABEL}_$$.txt
command -v timeout >/dev/null 2>&1 || { echo "Android timeout command missing"; exit 1; }
run() { echo; echo "--- $* ---"; timeout 10 "$@" 2>&1; }
{
    echo "Nfqttl Eclipse 3.0.0 diagnostic: $LABEL"
    date
    run uname -a
    run getprop ro.product.device
    run getprop ro.build.fingerprint
    run getprop ro.build.version.release
    run getprop ro.build.version.sdk
    run getprop gsm.network.type
    run getprop gsm.data.network.type
    run dumpsys telephony.registry
    run sh "$MODDIR/control.sh" status
    echo; echo "Worker logs:"
    for f in /data/adb/nfqttl-state/worker.*.log; do [ -f "$f" ] && { echo "--- $f ---"; tail -n 80 "$f"; }; done
    run ip -o link show
    run ip -4 addr show
    run ip -6 addr show
    run ip -4 rule show
    run ip -6 rule show
    run ip -4 route show table all
    run ip -6 route show table all
    run ip -s link show
    run ip neigh show
    run cat /proc/net/netfilter/nfnetlink_queue
    run iptables -w 2 -t mangle -S
    run ip6tables -w 2 -t mangle -S
    run settings get global tether_offload_disabled
    run device_config get connectivity tether_enable_bpf_offload
    run dumpsys tethering
    run dumpsys connectivity
    run dumpsys wifi
    run ping -n -c 10 -W 1 1.1.1.1
    run ping -n -c 10 -W 1 8.8.8.8
    echo; echo "Module log:"
    tail -n 160 /data/adb/nfqttl-state/service.log 2>/dev/null
} > "$OUT" 2>&1
if [ -s "$OUT" ]; then
    echo "$OUT"
    echo "Contains network addresses, Wi-Fi and telephony state; review before sharing."
else
    echo "Cannot write diagnostics to Downloads"; exit 1
fi
