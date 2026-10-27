# Development — Nfqttl 4.4

Rust 2021; no crates or network dependencies in Cargo.lock.
64-bit Linux syscall ABI, static musl AArch64 binary for Android arm64-v8a.
The application does not link against Android's libnetfilter_queue.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build
python3 tests/integration.py
python3 tests/verify_wire.py   # live AF_PACKET check on lo, needs root
python3 tests/installer.py
sh src/build.sh
```

`build.sh` installs the musl target via rustup, uses Rust's bundled rust-lld,
checks AArch64 architecture and absence of ELF interpreter, then creates the
installable module. `sh src/source-package.sh` creates the source ZIP.
Rust release profile: opt-level=3, LTO=fat, codegen-units=1, stripped, panic=abort.
The source archive includes Cargo.lock, tests, frontend, and build scripts.

Optional UI check: install Node Playwright and Chromium, then run
`node tests/webui.cjs`. `CHROME_BIN` may point to a local Chromium/Chrome binary.
A browser-free logic check uses `npm install jsdom` followed by
`node tests/webui-dom.cjs`. The KSU bridge is mocked for host testing; actual Android WebView/root manager
permissions need an on-device check.

Runtime chain names retain v40 suffix for cleanup compatibility. Queues start
at 6464. Each worker binds its own netlink port ID to getpid(). Kernel mode has
zero workers. Two inactive payload chains allow rule replacement without
flushing the currently active payload. IPv4/IPv6 table changes are sequential,
not an atomic cross-family transaction. Initial activation attaches one hook.
Legacy module jumps are removed before deleting chains; unrelated tables and
Android NAT/filter rules are never flushed.

`NFQTTL_STATE`, `NFQTTL_IPTABLES`, `NFQTTL_IP6TABLES` override paths for isolated
host tests. They are process environment overrides, not config.conf settings.
`tests/mock_android.py` simulates routes, netd chain resets, settings and xtables;
no host firewall modifications occur. NFQUEUE parser tests operate on bytes;
live kernel packet throughput is not benchmarked by those tests.

`configure` uses a controller flock, validates a temporary full config,
optionally stops the running supervisor, writes the backup, renames the new
config, and restarts. Flock files remain in the state directory: deleting a
locked inode could let a second process lock a different inode. State writes
use temporary files and rename. Offload rollback checks current values against
owned values before restoration. Persistent state is private (0700).

KernelSU WebUI calls the documented native exec(command, optionsJson,
callbackName) API; no remote assets or runtime npm dependency are used.
Only numeric and enumerated settings reach the shell from the frontend; raw
logs are displayed with textContent.

## v4.3 CAKE SQM
src/qos.rs implements a bounded NETLINK_ROUTE client and optional CAKE lifecycle.
Rates use kbit/s externally and bytes/s in TCA_CAKE_BASE_RATE64. Root changes use
CREATE|EXCL, private write-before-apply journals, ifindex + handle + full CAKE
options ownership comparison. Only kernel-default roots are accepted; custom
qdisc children are preserved. Config is explicit and opt-in. See NETWORK_RU.md.

## v4.4 verify
`src/verify.rs` combines two observations over a window: packet deltas of the
active payload chain (proves the FORWARD hook sees tethered packets) and an
AF_PACKET `SOCK_DGRAM` tap on each upstream interface (egress TTL, version
nibble based so raw-IP rmnet/tun devices work). All decisions live in the pure
`judge()`; exit codes: 0 pass, 2 inconclusive, 3 fail, 1 error. A TTL is
"foreign" when it is neither the configured value nor the phone default
(`ip_default_ttl`). A leak needs >=10 foreign packets and >5% of the sample.
IPv6 wire values are informational only (CLAT can alter them).
`tests/mock_android.py` now prints iptables counters in the real `-nvx` format
from `counters.json`.
