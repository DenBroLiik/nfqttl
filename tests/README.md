# Verification

- `cargo test`: config parsing/ranges, IPv4 checksum/options, malformed NFQUEUE
  attributes, queue IDs, truncated GSO handling, IPv6/CLAT/Wi-Fi classification,
  nonblocking subprocess capture with large stdout/stderr.
- `cargo build && python3 tests/integration.py`: isolated Android/netd simulation,
  payload/hook resets, duplicate hooks, IPv6-only USB upstream switch, idle
  cleanup, flock ownership, pause/start, atomic config updates, rollback of
  offload and protection of external setting changes.
- `python3 tests/verify_wire.py`: live AF_PACKET tap on `lo` (root): TTL 64 passes,
  TTL 63 leak fails with exit 3, noise tolerance, idle link, missing interface.
- `python3 tests/installer.py`: update migration and invalid-config rejection.
- `node tests/webui-dom.cjs` (jsdom): bridge commands and form/input behavior.
- `node tests/webui.cjs`: mocked KernelSU bridge and mobile viewport, config
  save, start/stop, logs, doctor, text escaping and horizontal overflow.

Live RF throughput, actual Android IPA/BPF behavior and battery use must be
verified on the phone; the simulator does not reproduce kernel forwarding.

CAKE lifecycle tests use a fake qdisc backend. They cover recovery, idempotence,
rate changes, custom roots/children and external changes. They do not verify
Android kernel netlink operations or radio performance. `qos` is a read-only
live qdisc inspection command for the installed phone.
