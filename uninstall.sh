#!/system/bin/sh
MODDIR=${0%/*}
"$MODDIR/nfqttl" stop --module-dir "$MODDIR" 2>/dev/null || true
