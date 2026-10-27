#!/system/bin/sh
MODDIR=${0%/*}
if [ "$#" -eq 0 ]; then set -- status; fi
exec "$MODDIR/nfqttl" "$@" --module-dir "$MODDIR"
