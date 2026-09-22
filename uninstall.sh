#!/system/bin/sh
MODDIR=${0%/*}
sh "$MODDIR/control.sh" stop
# Retain baseline and diagnostics if restoration cannot finish during uninstall.
