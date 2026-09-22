# Migration v3 -> v4 Rust

| v3 | v4 Rust |
|---|---|
| `service.sh` ~218 lines | 3-line launcher -> `nfqttl daemon` |
| `common.sh` ~249 lines | removed; firewall/network/offload/state logic is Rust |
| `src/nfqttl-lite.c` | `src/nfqueue.rs` |
| `src/packet.h` | `src/packet.rs` |
| `control.sh` logic | `src/ctl.rs` |
| 1 s route polling only | `NETLINK_ROUTE` wakeups + 1 s health timeout |
| queue processes | separate Rust worker processes |
| `nfqttl_v30*` chains | `nfqttl_v40*`; startup cleanup removes old v3 chains |
| ambiguous explicit IPv6 block behavior | strict `block` semantics |

Configuration keys and state directory `/data/adb/nfqttl-state` are retained so an existing `config.conf` can be migrated by `customize.sh`.
