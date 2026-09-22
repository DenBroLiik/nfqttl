#!/system/bin/sh
MODDIR=${0%/*}
. "$MODDIR/common.sh"
umask 077
mkdir -p "$STATE"

if ! mkdir "$STATE/lock" 2>/dev/null; then
    [ -f "$STATE/lock/pid" ] || sleep 1
    lock_pid=$(cat "$STATE/lock/pid" 2>/dev/null)
    owned_pid "$lock_pid" "$MODDIR/service.sh" && exit 0
    rm -f "$STATE/lock/pid"; rmdir "$STATE/lock" 2>/dev/null || exit 1
    mkdir "$STATE/lock" 2>/dev/null || exit 1
fi
echo $$ > "$STATE/lock/pid"

TTL=64 BACKEND=auto WORKERS=4 DOWNSTREAMS="" UPSTREAMS="" DISABLE_OFFLOAD=1
IPV6_MODE=auto IPV6_HL=64 MAX_FAILURES=6 COOLDOWN=3 MAX_BACKLOG=768 STALL_LIMIT=3
[ -f "$MODDIR/config.conf" ] && . "$MODDIR/config.conf"
case "$TTL" in ''|*[!0-9]*) TTL=64;; esac; [ "$TTL" -ge 1 ] && [ "$TTL" -le 255 ] || TTL=64
case "$IPV6_HL" in ''|*[!0-9]*) IPV6_HL=64;; esac; [ "$IPV6_HL" -ge 1 ] && [ "$IPV6_HL" -le 255 ] || IPV6_HL=64
case "$WORKERS" in ''|*[!0-9]*) WORKERS=4;; esac; [ "$WORKERS" -ge 1 ] && [ "$WORKERS" -le 8 ] || WORKERS=4
case "$MAX_FAILURES" in ''|*[!0-9]*) MAX_FAILURES=6;; esac; [ "$MAX_FAILURES" -ge 1 ] && [ "$MAX_FAILURES" -le 20 ] || MAX_FAILURES=6
case "$COOLDOWN" in ''|*[!0-9]*) COOLDOWN=3;; esac; [ "$COOLDOWN" -ge 1 ] && [ "$COOLDOWN" -le 60 ] || COOLDOWN=3
case "$MAX_BACKLOG" in ''|*[!0-9]*) MAX_BACKLOG=768;; esac; [ "$MAX_BACKLOG" -ge 32 ] && [ "$MAX_BACKLOG" -le 8192 ] || MAX_BACKLOG=768
case "$STALL_LIMIT" in ''|*[!0-9]*) STALL_LIMIT=3;; esac; [ "$STALL_LIMIT" -ge 2 ] && [ "$STALL_LIMIT" -le 10 ] || STALL_LIMIT=3
case "$BACKEND" in auto|kernel|nfqueue) ;; *) BACKEND=auto;; esac
case "$IPV6_MODE" in auto|normalize|block|pass) ;; *) IPV6_MODE=auto;; esac

ACTIVE="" ACTIVE6="" MODE="" V6MODE=pass ACTIVE_WORKERS=1 FAILURES=0
finish() {
    trap - EXIT INT TERM
    [ -n "$IPT" ] && cleanup_rules4 || true
    [ -n "$IP6T" ] && cleanup_rules6 || true
    stop_workers
    restore_offload
    rm -f "$STATE/lock/pid"; rmdir "$STATE/lock" 2>/dev/null
}
trap finish EXIT
trap 'exit 0' INT TERM

i=0
while [ "$(getprop sys.boot_completed)" != 1 ] && [ "$i" -lt 60 ]; do sleep 2; i=$((i + 1)); done
select_iptables || { log_msg "ERROR: usable Android iptables not found"; exit 1; }
cleanup_rules || exit 1

# Clean old nft experiment table from 2.8.x only.
command -v nft >/dev/null 2>&1 && nft delete table inet nfqttl_table 2>/dev/null
stop_workers

log_msg "v3.0.0 starting; requested=$BACKEND ttl=$TTL workers=$WORKERS ipv6=$IPV6_MODE"
if [ "$BACKEND" != nfqueue ]; then
    p=nfqttl_tprobe
    ipt -N "$p" 2>/dev/null || ipt -F "$p" 2>/dev/null
    if ipt -A "$p" -j TTL --ttl-set "$TTL" 2>>"$STATE/service.log"; then MODE=kernel; fi
    ipt -F "$p" 2>/dev/null; ipt -X "$p" 2>/dev/null
fi
if [ -z "$MODE" ]; then
    [ "$BACKEND" = kernel ] && { log_msg "ERROR: kernel TTL target unavailable"; exit 1; }
    MODE=nfqueue
    if probe_queue_balance; then ACTIVE_WORKERS=$WORKERS; else ACTIVE_WORKERS=1; fi
fi

if [ "$IPV6_MODE" = pass ]; then
    V6MODE=pass
elif [ -z "$IP6T" ]; then
    if [ "$IPV6_MODE" = normalize ]; then
        log_msg "ERROR: IPv6 HL normalization requested but ip6tables is unavailable"; exit 1
    fi
    V6MODE=pass-no-ip6tables
    log_msg "WARNING: ip6tables unavailable; forwarded IPv6 cannot be normalized or blocked"
elif probe_ipv6_hl; then
    V6MODE=normalize
elif [ "$IPV6_MODE" = normalize ]; then
    log_msg "ERROR: IPv6 HL target requested but unavailable"; exit 1
else
    V6MODE=block
fi

echo "$MODE" > "$STATE/backend"
echo "$ACTIVE_WORKERS" > "$STATE/workers"
echo "$V6MODE" > "$STATE/ipv6_mode"
apply_offload
log_msg "backend=$MODE active_workers=$ACTIVE_WORKERS ipv6_effective=$V6MODE; restart hotspot if already active"

install_v4() {
    [ "$ACTIVE" = "$CHAIN_A" ] && new=$CHAIN_B || new=$CHAIN_A
    ipt -N "$new" 2>/dev/null; ipt -F "$new" || return 1
    for inif in $DOWN; do
        for outif in $UP; do
            [ "$inif" = "$outif" ] && continue
            if [ "$MODE" = kernel ]; then
                ipt -A "$new" -i "$inif" -o "$outif" -j TTL --ttl-set "$TTL" || return 1
            elif [ "$ACTIVE_WORKERS" -gt 1 ]; then
                end=$((QUEUE_BASE + ACTIVE_WORKERS - 1))
                ipt -A "$new" -i "$inif" -o "$outif" -j NFQUEUE --queue-balance "$QUEUE_BASE:$end" --queue-bypass || return 1
            else
                ipt -A "$new" -i "$inif" -o "$outif" -j NFQUEUE --queue-num "$QUEUE_BASE" --queue-bypass || return 1
            fi
        done
    done
    ipt -N "$CHAIN_HOOK" 2>/dev/null
    if [ -n "$ACTIVE" ]; then
        ipt -R "$CHAIN_HOOK" 1 -j "$new" || return 1
    else
        ipt -F "$CHAIN_HOOK" || return 1
        ipt -A "$CHAIN_HOOK" -j "$new" || return 1
        ipt -C FORWARD -j "$CHAIN_HOOK" >/dev/null 2>&1 || ipt -I FORWARD 1 -j "$CHAIN_HOOK" || return 1
    fi
    if [ -n "$ACTIVE" ]; then ipt -F "$ACTIVE" 2>/dev/null; fi
    ACTIVE=$new
    return 0
}

install_v6() {
    case "$V6MODE" in pass|pass-no-ip6tables) cleanup_rules6; ACTIVE6=""; return 0;; esac
    [ -n "$IP6T" ] || return 0
    [ "$ACTIVE6" = "$CHAIN6_A" ] && new6=$CHAIN6_B || new6=$CHAIN6_A
    ip6t -N "$new6" 2>/dev/null; ip6t -F "$new6" || return 1
    for inif in $DOWN; do
        for outif in $UP; do
            [ "$inif" = "$outif" ] && continue
            if [ "$V6MODE" = normalize ]; then
                ip6t -A "$new6" -i "$inif" -o "$outif" -j HL --hl-set "$IPV6_HL" || return 1
            else
                ip6t -A "$new6" -i "$inif" -o "$outif" -j DROP || return 1
            fi
        done
    done
    ip6t -N "$CHAIN6_HOOK" 2>/dev/null
    if [ -n "$ACTIVE6" ]; then
        ip6t -R "$CHAIN6_HOOK" 1 -j "$new6" || return 1
    else
        ip6t -F "$CHAIN6_HOOK" || return 1
        ip6t -A "$CHAIN6_HOOK" -j "$new6" || return 1
        ip6t -C FORWARD -j "$CHAIN6_HOOK" >/dev/null 2>&1 || ip6t -I FORWARD 1 -j "$CHAIN6_HOOK" || return 1
    fi
    [ -n "$ACTIVE6" ] && ip6t -F "$ACTIVE6" 2>/dev/null
    ACTIVE6=$new6
    return 0
}

recover() {
    log_msg "RECOVERY: $*"
    cleanup_rules4 || true; cleanup_rules6 || true
    ACTIVE=""; ACTIVE6=""; stop_workers
    FAILURES=$((FAILURES + 1))
    if [ "$FAILURES" -ge "$MAX_FAILURES" ]; then
        if [ "$MODE" = nfqueue ] && [ "$ACTIVE_WORKERS" -gt 1 ]; then
            ACTIVE_WORKERS=$(((ACTIVE_WORKERS + 1) / 2))
            [ "$ACTIVE_WORKERS" -lt 1 ] && ACTIVE_WORKERS=1
            echo "$ACTIVE_WORKERS" > "$STATE/workers"
            log_msg "DEGRADE: reducing NFQUEUE workers to $ACTIVE_WORKERS after repeated failures"
            FAILURES=0
        else
            log_msg "ERROR: repeated backend failures; stopping to avoid unstable firewall state"
            return 1
        fi
    fi
    sleep "$COOLDOWN"
    LAST=""; LAST_Q=""; LAST_DROPS=""; STALLED=0; STABLE=0
    return 0
}

LAST="" LAST_Q="" LAST_DROPS="" STALLED=0 WARN_BACKLOG=0 STABLE=0
while :; do
    if [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ] || [ -f "$STATE/paused" ]; then
        log_msg "stopping: disabled/removed/paused"; exit 0
    fi

    discover_links
    SIG="$DOWN|$UP"
    hook_ok=0
    [ -n "$ACTIVE" ] && ipt -C FORWARD -j "$CHAIN_HOOK" >/dev/null 2>&1 && hook_ok=1
    hook6_ok=1
    case "$V6MODE" in
        normalize|block)
            hook6_ok=0
            [ -n "$ACTIVE6" ] && [ -n "$IP6T" ] && ip6t -C FORWARD -j "$CHAIN6_HOOK" >/dev/null 2>&1 && hook6_ok=1
            ;;
    esac
    if [ "$SIG" != "$LAST" ] || { [ -n "$DOWN" ] && [ -n "$UP" ] && { [ "$hook_ok" -ne 1 ] || [ "$hook6_ok" -ne 1 ]; }; }; then
        if [ -z "$DOWN" ] || [ -z "$UP" ]; then
            cleanup_rules4 || exit 1; cleanup_rules6 || exit 1
            stop_workers; ACTIVE=""; ACTIVE6=""
        else
            if [ "$MODE" = nfqueue ] && ! workers_healthy; then
                stop_workers
                if ! start_workers; then recover "worker startup failed" || exit 1; continue; fi
            fi
            if ! install_v4 || ! install_v6; then recover "rule installation failed" || exit 1; continue; fi
            echo "downstream:$DOWN upstream:$UP" > "$STATE/interfaces"
            log_msg "rules active: $(cat "$STATE/interfaces")"
        fi
        LAST=$SIG; STALLED=0; LAST_Q=""; LAST_DROPS=""; STABLE=0
    fi

    if [ "$MODE" = nfqueue ] && [ -n "$ACTIVE" ]; then
        if ! workers_healthy; then recover "worker/queue disappeared" || exit 1; continue; fi
        QS=$(queue_stats)
        rows=$(printf '%s\n' "$QS" | awk 'NF==6{n++} END{print n+0}')
        if [ "$rows" -ne "$ACTIVE_WORKERS" ]; then recover "queue stats incomplete rows=$rows expected=$ACTIVE_WORKERS" || exit 1; continue; fi
        QLEN=$(printf '%s\n' "$QS" | awk '{s+=$3} END{print s+0}')
        DROPS=$(printf '%s\n' "$QS" | awk '{k+=$4;u+=$5} END{print k":"u}')
        QPROGRESS=$(printf '%s\n' "$QS" | awk '{printf "%s:%s:%s;",$1,$3,$6}')
        if [ "$QLEN" -gt 0 ] && [ "$QPROGRESS" = "$LAST_Q" ]; then STALLED=$((STALLED + 1)); else STALLED=0; fi
        if [ -n "$LAST_DROPS" ] && [ "$DROPS" != "$LAST_DROPS" ]; then
            log_msg "WARNING: NFQUEUE drops changed $LAST_DROPS -> $DROPS (backlog=$QLEN); keeping service active"
        fi
        if [ "$QLEN" -ge "$MAX_BACKLOG" ]; then
            WARN_BACKLOG=$((WARN_BACKLOG + 1))
            [ $((WARN_BACKLOG % 5)) -eq 1 ] && log_msg "WARNING: NFQUEUE backlog=$QLEN (limit=$MAX_BACKLOG)"
        else WARN_BACKLOG=0; fi
        if [ "$STALLED" -ge "$STALL_LIMIT" ]; then recover "queue stalled backlog=$QLEN drops=$DROPS" || exit 1; continue; fi
        LAST_Q=$QPROGRESS; LAST_DROPS=$DROPS
        STABLE=$((STABLE + 1)); [ "$STABLE" -ge 60 ] && FAILURES=0
    fi
    sleep 1
done
