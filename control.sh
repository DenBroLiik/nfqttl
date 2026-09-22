#!/system/bin/sh
MODDIR=${0%/*}
exec "$MODDIR/nfqttl" "${1:-status}" --module-dir "$MODDIR"
