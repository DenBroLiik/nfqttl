#!/system/bin/sh
MODDIR=${0%/*}
exec "$MODDIR/nfqttl" toggle --module-dir "$MODDIR"
