# Nfqttl Eclipse 3.0.0 — developer notes

## Target

Primary target: Xiaomi `stone`, RisingOS, Eclipse kernel, arm64-v8a. Current Eclipse `stone_defconfig` has NFQUEUE and BPF support but lacks xt_HL/IPv4 TTL target, so stock builds use the NFQUEUE fallback.

## Data path

1. `service.sh` discovers tether downstream and active uplinks from Android policy routing tables.
2. Native `TTL --ttl-set` is probed first. If unavailable, `NFQUEUE` is used.
3. NFQUEUE uses queues starting at 6464. `WORKERS=4` requests 6464..6467 with `--queue-balance`.
4. Each arm64 worker requests `NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO`, queue maxlen 1024, and a 4 MiB receive socket buffer.
5. The worker changes only IPv4 TTL and recomputes the IPv4 header checksum. TCP/UDP payload and transport headers are untouched.
6. Rules are installed behind a stable `nfqttl_v30h` hook. Route changes build the inactive leaf then `-R` the hook, avoiding the old double-queue window.

## Why GSO

Without `NFQA_CFG_F_GSO`, the kernel normalizes/segments GSO packets before sending them to NFQUEUE. That increases packet rate and userspace/netlink overhead. v3 keeps GSO packets intact where supported.

## Watchdog policy

- Worker death, missing queue ownership, or a queue that stops making sequence progress triggers recovery.
- A changed packet-drop counter is warning telemetry, not an immediate circuit-break condition.
- Repeated hard failures degrade worker count 4 -> 2 -> 1 before the supervisor gives up.
- 60 seconds of stable processing resets the failure counter.

## IPv6

`IPV6_MODE=auto` probes `ip6tables -j HL --hl-set`. If the target is unavailable it blocks forwarded tether IPv6 to avoid a separate hop-limit/address path that bypasses IPv4 TTL rewriting. If `ip6tables` itself is unavailable, effective mode is `pass-no-ip6tables` with an explicit warning; `pass` leaves IPv6 untouched by request.

The included kernel patch enables the dependency and targets:

- `CONFIG_NETFILTER_ADVANCED=y`
- `CONFIG_NETFILTER_XT_TARGET_HL=y`
- `CONFIG_IP_NF_TARGET_TTL=y`
- `CONFIG_IP6_NF_TARGET_HL=y`

With these options built into Eclipse, the module can use in-kernel rewriting and should be preferable to NFQUEUE for throughput/latency.

## Build

Worker source: `src/nfqttl-lite.c`.

```sh
cd src/..
ZIG=zig ./src/build.sh
```

For the provided stone package only `libs/arm64-v8a/nfqttl-lite` is shipped. The source build script can still produce other ABIs for development.

## Validation checklist

- `sh -n` all shell scripts.
- Compile/run `tests/test_worker.c` under ASan/UBSan.
- Verify arm64 binary reports `maxlen=1024 gso=1`.
- On phone: test hotspot speed, packet loss, SIM call, VoWiFi call, route changes, 1/2/3+ client devices.
- Capture `diagnose.sh before`, `during`, and `after` if latency or throughput regresses.
