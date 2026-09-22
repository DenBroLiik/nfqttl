# Nfqttl Eclipse Rust 4.0 — developer notes

## Architecture

One Rust executable has several roles:

```text
service.sh -> nfqttl daemon
                  |-- NETLINK_ROUTE event watcher
                  |-- iptables/ip6tables atomic chain manager
                  |-- offload ownership/restore
                  |-- NFQUEUE watchdog
                  `-- spawns N x `nfqttl worker`

control.sh -> nfqttl status|start|stop|restart
```

Workers are separate processes intentionally. Every NFQUEUE socket binds its own netlink port id/PID and iptables `--queue-balance` can distribute packets over queues 6464..646N in parallel. A single multi-threaded process would require different port-id handling and would make v3-compatible watchdog ownership less transparent.

## Data path

1. Daemon probes `TTL --ttl-set`.
2. When present, kernel backend is used and no Rust packet worker is launched.
3. Otherwise daemon probes `--queue-balance`, starts 1..8 Rust workers and only then attaches forwarding rules.
4. Worker binds `NETLINK_NETFILTER`, configures queue copy mode, maxlen=1024 and flags FAIL_OPEN+GSO.
5. Only IPv4 packets at `NF_INET_FORWARD` are rewritten; TCP/UDP and payload are not changed.
6. Daemon watches `/proc/net/netfilter/nfnetlink_queue` for queue ownership, backlog, drops and sequence progress.
7. Route/link/address changes wake the daemon through `NETLINK_ROUTE`; a 1s poll timeout doubles as watchdog cadence.

## Firewall atomicity

The stable hooks are now `nfqttl_v40h` and `nfqttl6_v40h`. Two leaf chains (`v40a`, `v40b`) alternate. New rules are fully populated before hook rule 1 is replaced. Cleanup also removes v3/v2.9 chain names for migration.

## IPv6 policy

- `auto`: normalize using `HL --hl-set` when supported, otherwise block forwarded tether IPv6.
- `normalize`: fail startup if HL target is unavailable.
- `block`: always DROP forwarded tether IPv6. This fixes the v3 behavior where explicit block could become normalize when HL existed.
- `pass`: untouched.

## Why kernel code remains C/Linux netfilter

The target Eclipse tree is Linux 5.4.303 and has no Rust-for-Linux build infrastructure. Rust is therefore used where it is valuable and deployable today: daemon, state machine, route watcher, CLI and NFQUEUE packet engine. The included kernel patch still enables `CONFIG_IP_NF_TARGET_TTL`/`CONFIG_IP6_NF_TARGET_HL` for the fastest path.

## Validation

Host:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

Target build:

```sh
./src/build.sh
file libs/arm64-v8a/nfqttl
```

Phone validation should repeat v3 tests: hotspot speed + ping, 1/2/3+ clients, mobile route changes, SIM call, VoWiFi call, worker kill/recovery, queue backlog/drops and IPv6 policy.
