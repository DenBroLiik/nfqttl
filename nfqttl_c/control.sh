#!/system/bin/sh
MODDIR=${0%/*}
. "$MODDIR/common.sh"
umask 077
mkdir -p "$STATE"
case "$1" in
    status)
        cat "$MODDIR/module.prop"
        echo "Backend:"; cat "$STATE/backend" 2>/dev/null
        echo "NFQUEUE workers:"; cat "$STATE/workers" 2>/dev/null
        echo "IPv6 mode:"; cat "$STATE/ipv6_mode" 2>/dev/null
        echo "Supervisor:"; cat "$STATE/lock/pid" 2>/dev/null
        echo "Worker pids:"
        for pf in "$STATE"/worker.*.pid; do
            [ -f "$pf" ] || continue
            q=${pf##*/worker.}; q=${q%.pid}
            echo "$q: $(cat "$pf")"
        done
        echo "Paused:"; [ -f "$STATE/paused" ] && echo yes || echo no
        cat "$STATE/interfaces" 2>/dev/null
        if select_iptables; then
            ACTIVE_WORKERS=$(cat "$STATE/workers" 2>/dev/null); case "$ACTIVE_WORKERS" in ''|*[!0-9]*) ACTIVE_WORKERS=1;; esac
            echo "Queue (queue, pid, length, kernel drops, userspace drops, sequence):"
            queue_stats
            echo "IPv4 hook counters:"; ipt -L "$CHAIN_HOOK" -nvx 2>/dev/null
            [ -n "$IP6T" ] && { echo "IPv6 hook counters:"; ip6t -L "$CHAIN6_HOOK" -nvx 2>/dev/null; }
        fi
        tail -n 30 "$STATE/service.log" 2>/dev/null
        ;;
    stop)
        touch "$STATE/paused"
        pid=$(cat "$STATE/lock/pid" 2>/dev/null)
        if owned_pid "$pid" "$MODDIR/service.sh"; then
            kill -TERM "$pid" 2>/dev/null
            i=0
            while owned_pid "$pid" "$MODDIR/service.sh" && [ "$i" -lt 15 ]; do sleep 1; i=$((i + 1)); done
            if owned_pid "$pid" "$MODDIR/service.sh"; then echo "Supervisor still stopping; reboot if necessary."; exit 1; fi
        fi
        select_iptables && cleanup_rules
        stop_workers
        restore_offload
        echo "Stopped. Restart hotspot if you want Android offload restored immediately."
        ;;
    start)
        if [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ]; then echo "Enable module in Magisk first."; exit 1; fi
        rm -f "$STATE/paused"
        sh "$MODDIR/service.sh" >/dev/null 2>&1 &
        echo "Start requested. Check status/service.log."
        ;;
    restart)
        sh "$0" stop || exit 1
        rm -f "$STATE/paused"
        sh "$MODDIR/service.sh" >/dev/null 2>&1 &
        echo "Restart requested."
        ;;
    *) echo "Usage: sh $MODDIR/control.sh status|stop|start|restart"; exit 2;;
esac
