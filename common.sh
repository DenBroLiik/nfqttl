#!/system/bin/sh
# Shared helpers. Caller provides MODDIR. No side effects when sourced.
STATE=/data/adb/nfqttl-state
QUEUE_BASE=6464
CHAIN_HOOK=nfqttl_v30h
CHAIN_A=nfqttl_v30a
CHAIN_B=nfqttl_v30b
CHAIN6_HOOK=nfqttl6_v30h
CHAIN6_A=nfqttl6_v30a
CHAIN6_B=nfqttl6_v30b

log_msg() {
    mkdir -p "$STATE"
    if [ -f "$STATE/service.log" ] && [ "$(wc -c < "$STATE/service.log")" -gt 262144 ]; then
        mv -f "$STATE/service.log" "$STATE/service.log.1"
    fi
    echo "$(date '+%F %T') $*" >> "$STATE/service.log"
}

ipt() { "$IPT" -w 2 -t mangle "$@"; }
ip6t() { "$IP6T" -w 2 -t mangle "$@"; }

select_iptables() {
    IPT=""; IP6T=""
    for candidate in /system/bin/iptables /system/bin/iptables-legacy /system/xbin/iptables-legacy; do
        if [ -x "$candidate" ] && "$candidate" -w 2 -t mangle -S FORWARD >/dev/null 2>&1; then
            IPT=$candidate
            break
        fi
    done
    [ -n "$IPT" ] || return 1
    for candidate in /system/bin/ip6tables /system/bin/ip6tables-legacy /system/xbin/ip6tables-legacy; do
        if [ -x "$candidate" ] && "$candidate" -w 2 -t mangle -S FORWARD >/dev/null 2>&1; then
            IP6T=$candidate
            break
        fi
    done
    return 0
}

detach_jump4() {
    parent=$1 target=$2 n=0
    while ipt -C "$parent" -j "$target" >/dev/null 2>&1; do
        ipt -D "$parent" -j "$target" || return 1
        n=$((n + 1)); [ "$n" -lt 16 ] || return 1
    done
    return 0
}

detach_jump6() {
    [ -n "$IP6T" ] || return 0
    parent=$1 target=$2 n=0
    while ip6t -C "$parent" -j "$target" >/dev/null 2>&1; do
        ip6t -D "$parent" -j "$target" || return 1
        n=$((n + 1)); [ "$n" -lt 16 ] || return 1
    done
    return 0
}

cleanup_rules4() {
    detach_jump4 FORWARD "$CHAIN_HOOK" || return 1
    for c in "$CHAIN_HOOK" "$CHAIN_A" "$CHAIN_B" nfqttl_v29a nfqttl_v29b nfqttl_fwd; do
        ipt -F "$c" 2>/dev/null
        ipt -X "$c" 2>/dev/null
    done
    return 0
}

cleanup_rules6() {
    [ -n "$IP6T" ] || return 0
    detach_jump6 FORWARD "$CHAIN6_HOOK" || return 1
    for c in "$CHAIN6_HOOK" "$CHAIN6_A" "$CHAIN6_B"; do
        ip6t -F "$c" 2>/dev/null
        ip6t -X "$c" 2>/dev/null
    done
    return 0
}

cleanup_rules() { cleanup_rules4 && cleanup_rules6; }

owned_pid() {
    case "$1" in ''|*[!0-9]*) return 1;; esac
    [ -r "/proc/$1/cmdline" ] || return 1
    tr '\000' '\n' < "/proc/$1/cmdline" | grep -Fqx "$2"
}

queue_owner() {
    awk -v q="$1" '$1 == q {print $2; exit}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null
}

queue_stats() {
    q_end=$((QUEUE_BASE + ACTIVE_WORKERS - 1))
    awk -v a="$QUEUE_BASE" -v b="$q_end" '$1 >= a && $1 <= b {print $1, $2, $3, $6, $7, $8}' \
        /proc/net/netfilter/nfnetlink_queue 2>/dev/null | sort -n
}

stop_workers() {
    for pf in "$STATE"/worker.*.pid; do
        [ -f "$pf" ] || continue
        pid=$(cat "$pf" 2>/dev/null)
        if owned_pid "$pid" "$MODDIR/nfqttl-lite"; then kill -TERM "$pid" 2>/dev/null; fi
    done
    sleep 1
    for pf in "$STATE"/worker.*.pid; do
        [ -f "$pf" ] || continue
        pid=$(cat "$pf" 2>/dev/null)
        if owned_pid "$pid" "$MODDIR/nfqttl-lite"; then kill -KILL "$pid" 2>/dev/null; fi
        rm -f "$pf"
    done
    rm -f "$STATE/worker.pid"
}

start_workers() {
    q=$QUEUE_BASE
    q_end=$((QUEUE_BASE + ACTIVE_WORKERS - 1))
    while [ "$q" -le "$q_end" ]; do
        owner=$(queue_owner "$q")
        [ -z "$owner" ] || { log_msg "ERROR: queue $q already owned by pid=$owner"; return 1; }
        q=$((q + 1))
    done
    [ -x "$MODDIR/nfqttl-lite" ] || return 1
    q=$QUEUE_BASE
    while [ "$q" -le "$q_end" ]; do
        log="$STATE/worker.$q.log"
        [ -f "$log" ] && mv -f "$log" "$log.1"
        "$MODDIR/nfqttl-lite" -n "$q" -t "$TTL" > "$log" 2>&1 &
        pid=$!
        echo "$pid" > "$STATE/worker.$q.pid"
        [ "$q" -eq "$QUEUE_BASE" ] && echo "$pid" > "$STATE/worker.pid"
        q=$((q + 1))
    done
    i=0
    while [ "$i" -lt 8 ]; do
        ok=1; q=$QUEUE_BASE
        while [ "$q" -le "$q_end" ]; do
            pid=$(cat "$STATE/worker.$q.pid" 2>/dev/null)
            owned_pid "$pid" "$MODDIR/nfqttl-lite" || ok=0
            [ "$(queue_owner "$q")" = "$pid" ] || ok=0
            grep -q '^READY ' "$STATE/worker.$q.log" 2>/dev/null || ok=0
            q=$((q + 1))
        done
        [ "$ok" -eq 1 ] && return 0
        sleep 1; i=$((i + 1))
    done
    return 1
}

workers_healthy() {
    q=$QUEUE_BASE; q_end=$((QUEUE_BASE + ACTIVE_WORKERS - 1))
    while [ "$q" -le "$q_end" ]; do
        pid=$(cat "$STATE/worker.$q.pid" 2>/dev/null)
        owned_pid "$pid" "$MODDIR/nfqttl-lite" || return 1
        [ "$(queue_owner "$q")" = "$pid" ] || return 1
        q=$((q + 1))
    done
    return 0
}

setting_read() {
    case "$1" in
        hw) settings get global tether_offload_disabled;;
        bpf) device_config get connectivity tether_enable_bpf_offload;;
    esac
}
setting_write() {
    case "$1:$2" in
        hw:null) settings delete global tether_offload_disabled;;
        hw:*) settings put global tether_offload_disabled "$2";;
        bpf:null) device_config delete connectivity tether_enable_bpf_offload;;
        bpf:*) device_config put connectivity tether_enable_bpf_offload "$2";;
    esac
}
apply_offload() {
    [ "$DISABLE_OFFLOAD" = 1 ] || return 0
    for key in hw bpf; do
        old=$(setting_read "$key" 2>/dev/null) || continue
        case "$key:$old" in hw:0|hw:1|hw:null|bpf:true|bpf:false|bpf:null) ;; *) continue;; esac
        [ -f "$STATE/offload.$key.before" ] || printf '%s\n' "$old" > "$STATE/offload.$key.before"
        [ "$key" = hw ] && new=1 || new=false
        if setting_write "$key" "$new" >/dev/null 2>&1 && [ "$(setting_read "$key" 2>/dev/null)" = "$new" ]; then
            echo "$new" > "$STATE/offload.$key.owned"
        else
            log_msg "WARNING: cannot disable $key offload"
        fi
    done
}
restore_offload() {
    for key in hw bpf; do
        [ -f "$STATE/offload.$key.owned" ] || continue
        now=$(setting_read "$key" 2>/dev/null) || continue
        ours=$(cat "$STATE/offload.$key.owned")
        if [ "$now" = "$ours" ]; then
            old=$(cat "$STATE/offload.$key.before")
            setting_write "$key" "$old" >/dev/null 2>&1 || continue
            [ "$(setting_read "$key" 2>/dev/null)" = "$old" ] || continue
        fi
        rm -f "$STATE/offload.$key.owned" "$STATE/offload.$key.before"
    done
}

valid_iface() {
    case "$1" in ''|*[!a-zA-Z0-9_.:-]*) return 1;; esac
    [ "${#1}" -le 15 ]
}

discover_links() {
    defaults=$(ip -4 route show table all 2>/dev/null | awk '$1 == "default" {for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}' | sort -u)
    addrs=$(ip -o -4 addr show 2>/dev/null | awk '{sub(/@.*/, "", $2); print $2}' | sort -u)
    UP=""
    [ -n "$UPSTREAMS" ] && up_list=$UPSTREAMS || up_list=$defaults
    for i in $up_list; do
        valid_iface "$i" || continue
        if [ -z "$UPSTREAMS" ]; then
            case "$i" in rmnet*|ccmni*|pdp*|wwan*|wlan*|eth*|tun*|tap*|wg*|tailscale*|zt*) ;; *) continue;; esac
        fi
        case " $UP " in *" $i "*) ;; *) UP="$UP $i";; esac
    done
    DOWN=""
    [ -n "$DOWNSTREAMS" ] && down_list=$DOWNSTREAMS || down_list=$addrs
    for i in $down_list; do
        valid_iface "$i" || continue
        case " $UP " in *" $i "*) continue;; esac
        if [ -z "$DOWNSTREAMS" ]; then
            case "$i" in ap*|ap_br*|wlan*|swlan*|softap*|wifi*|rndis*|usb*|ncm*|bnep*|bt-pan*|bt_pan*|br*) ;; *) continue;; esac
        fi
        case " $DOWN " in *" $i "*) ;; *) DOWN="$DOWN $i";; esac
    done
}

probe_queue_balance() {
    [ "$WORKERS" -gt 1 ] || return 1
    p=nfqttl_qprobe
    ipt -N "$p" 2>/dev/null || { ipt -F "$p" 2>/dev/null; }
    end=$((QUEUE_BASE + WORKERS - 1))
    if ipt -A "$p" -j NFQUEUE --queue-balance "$QUEUE_BASE:$end" --queue-bypass >/dev/null 2>&1; then
        ipt -F "$p" 2>/dev/null; ipt -X "$p" 2>/dev/null; return 0
    fi
    ipt -F "$p" 2>/dev/null; ipt -X "$p" 2>/dev/null; return 1
}

probe_ipv6_hl() {
    [ -n "$IP6T" ] || return 1
    p=nfqttl6_probe
    ip6t -N "$p" 2>/dev/null || { ip6t -F "$p" 2>/dev/null; }
    if ip6t -A "$p" -j HL --hl-set "$IPV6_HL" >/dev/null 2>&1; then
        ip6t -F "$p" 2>/dev/null; ip6t -X "$p" 2>/dev/null; return 0
    fi
    ip6t -F "$p" 2>/dev/null; ip6t -X "$p" 2>/dev/null; return 1
}
