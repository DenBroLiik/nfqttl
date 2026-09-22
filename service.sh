#!/system/bin/sh
MODDIR=${0%/*}
exec "$MODDIR/nfqttl" daemon --module-dir "$MODDIR"
