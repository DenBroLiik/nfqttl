//! `nfqttl verify`: evidence that tethered packets really take the normalised
//! path, instead of only evidence that the rules exist.
//!
//! Two independent observations are combined over a short window:
//!
//! 1. **Rule counters.** Packet deltas of the active payload chain prove that
//!    forwarded packets traverse the FORWARD hook and match a TTL/HL/NFQUEUE
//!    rule. Hardware/BPF offload that bypasses netfilter leaves them at zero.
//! 2. **Wire sample.** An AF_PACKET tap on every upstream interface records the
//!    TTL of packets as they actually leave the phone. Values that are neither
//!    the configured TTL nor the phone's own default are "foreign" and indicate
//!    un-normalised forwarded traffic.
//!
//! The decision logic is pure (`judge`) so it can be unit-tested off-device.
use crate::config::{valid_iface, Config, Ipv6Mode};
use crate::firewall::{Firewall, CHAIN6_HOOK, CHAIN_HOOK};
use crate::net;
use crate::sys::*;
use crate::util;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

pub const EXIT_PASS: i32 = 0;
pub const EXIT_INCONCLUSIVE: i32 = 2;
pub const EXIT_FAIL: i32 = 3;

const DEFAULT_SECONDS: u64 = 8;
/// A leak needs at least this many foreign-TTL packets, so a stray
/// `traceroute` or an app with a custom IP_TTL cannot fail the check alone.
const LEAK_MIN_PACKETS: u64 = 10;
/// ...and more than 1/LEAK_RATIO_DIV of all sampled IPv4 egress packets.
const LEAK_RATIO_DIV: u64 = 20;
/// Without rule counters, this many sampled packets are needed for a verdict.
const WIRE_ONLY_MIN_PACKETS: u64 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCount {
    pub input: String,
    pub output: String,
    pub target: String,
    pub pkts: u64,
}

/// Parses `iptables -t mangle -nvx -L CHAIN` rows:
/// `pkts bytes target prot opt in out source destination [options]`.
/// Header and `Chain` lines do not start with a number and are skipped.
pub fn parse_counters(text: &str) -> Vec<RuleCount> {
    text.lines()
        .filter_map(|line| {
            let w: Vec<&str> = line.split_whitespace().collect();
            if w.len() < 9 {
                return None;
            }
            let pkts = w[0].parse::<u64>().ok()?;
            w[1].parse::<u64>().ok()?;
            Some(RuleCount {
                input: w[5].to_string(),
                output: w[6].to_string(),
                target: w[2].to_string(),
                pkts,
            })
        })
        .collect()
}

/// Extracts the active payload chain from `-S <hook>` output.
pub fn active_chain(hook_rules: &str, hook: &str) -> Option<String> {
    let prefix = format!("-A {hook} -j ");
    hook_rules
        .lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Sum of per-rule packet increases between two snapshots of the same chain.
pub fn total_hits(before: &[RuleCount], after: &[RuleCount]) -> u64 {
    after
        .iter()
        .map(|a| {
            let b = before
                .iter()
                .find(|b| b.input == a.input && b.output == a.output && b.target == a.target)
                .map_or(0, |b| b.pkts);
            a.pkts.saturating_sub(b)
        })
        .sum()
}

pub struct Hist {
    counts: [u64; 256],
    pub total: u64,
}
impl Default for Hist {
    fn default() -> Self {
        Self {
            counts: [0; 256],
            total: 0,
        }
    }
}
impl Hist {
    pub fn add(&mut self, v: u8) {
        self.counts[v as usize] += 1;
        self.total += 1;
    }
    /// Packets whose value is not one of `ok`.
    pub fn foreign(&self, ok: &[u8]) -> u64 {
        (0..=255u8)
            .filter(|v| !ok.contains(v))
            .map(|v| self.counts[v as usize])
            .sum()
    }
    /// Most frequent values, descending.
    pub fn top(&self, n: usize) -> Vec<(u8, u64)> {
        let mut v: Vec<_> = (0..=255u8)
            .map(|x| (x, self.counts[x as usize]))
            .filter(|(_, c)| *c > 0)
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }
    fn describe(&self, label: &str) -> String {
        if self.total == 0 {
            return format!("{label}: no packets");
        }
        let top: Vec<String> = self
            .top(4)
            .iter()
            .map(|(v, c)| format!("{v}x{c}"))
            .collect();
        format!("{label}: {} packets, values {}", self.total, top.join(" "))
    }
}

/// Records the IPv4 TTL / IPv6 Hop Limit of one packet. The IP version nibble
/// is used instead of the link-layer protocol because rmnet/tun devices are
/// raw-IP and do not carry an Ethernet header.
pub fn observe(pkt: &[u8], h4: &mut Hist, h6: &mut Hist) {
    match pkt.first().map(|b| b >> 4) {
        Some(4) if pkt.len() >= 20 => h4.add(pkt[8]),
        Some(6) if pkt.len() >= 40 => h6.add(pkt[7]),
        _ => {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Inconclusive,
    Fail,
}
impl Outcome {
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Pass => EXIT_PASS,
            Self::Inconclusive => EXIT_INCONCLUSIVE,
            Self::Fail => EXIT_FAIL,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::Fail => "FAIL",
        }
    }
}

pub struct Evidence {
    /// Rule packet delta; `None` when counters were not collected.
    pub hits: Option<u64>,
    /// Sampled IPv4 packets leaving the upstream interfaces.
    pub wire4: u64,
    /// Of those, packets with a TTL that is neither configured nor the phone default.
    pub foreign4: u64,
    /// The active payload chain was replaced during the window.
    pub chain_changed: bool,
}

pub fn judge(e: &Evidence) -> (Outcome, &'static str) {
    let leak = e.foreign4 >= LEAK_MIN_PACKETS && e.foreign4 * LEAK_RATIO_DIV > e.wire4;
    match e.hits {
        Some(0) if leak => (
            Outcome::Fail,
            "packets leave with a foreign TTL while no rule matched: tethered traffic bypasses netfilter (hardware/BPF offload?). Restart the hotspot after offload is disabled",
        ),
        _ if leak => (
            Outcome::Fail,
            "a share of packets leaves with a foreign TTL: an interface pair is not covered, or another rule/offload path bypasses the hook",
        ),
        Some(n) if n > 0 => (
            Outcome::Pass,
            "tethered packets traverse the FORWARD hook and match the TTL/HL rule",
        ),
        Some(_) if e.chain_changed => (
            Outcome::Inconclusive,
            "rules were reinstalled during the window: run verify again",
        ),
        Some(_) => (
            Outcome::Inconclusive,
            "no forwarded packets matched: generate traffic from a hotspot client (a download) and run verify again",
        ),
        None if e.wire4 >= WIRE_ONLY_MIN_PACKETS => (
            Outcome::Pass,
            "sampled egress TTL is as configured (wire-only evidence: tethered and local packets cannot be told apart)",
        ),
        None => (
            Outcome::Inconclusive,
            "too few packets sampled on the wire: generate traffic and run verify again",
        ),
    }
}

struct Options {
    seconds: u64,
    ifaces: Vec<String>,
    wire_only: bool,
}
fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_string())
}
fn parse_options(args: &[String]) -> io::Result<Options> {
    let mut o = Options {
        seconds: DEFAULT_SECONDS,
        ifaces: vec![],
        wire_only: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--module-dir" => i += 1,
            "--seconds" => {
                i += 1;
                o.seconds = args
                    .get(i)
                    .and_then(|s| s.parse::<u64>().ok())
                    .filter(|s| (2..=60).contains(s))
                    .ok_or_else(|| invalid("--seconds expects a value from 2 to 60"))?;
            }
            "--iface" => {
                i += 1;
                let name = args
                    .get(i)
                    .filter(|s| valid_iface(s))
                    .ok_or_else(|| invalid("--iface expects a valid interface name"))?;
                if !o.ifaces.contains(name) {
                    o.ifaces.push(name.clone());
                }
            }
            "--wire-only" => o.wire_only = true,
            _ => return Err(invalid("unknown verify option")),
        }
        i += 1;
    }
    Ok(o)
}

struct Tap {
    fd: Fd,
}
fn open_tap(name: &str) -> io::Result<Tap> {
    if !valid_iface(name) {
        return Err(invalid("invalid interface name"));
    }
    let ifindex: i32 = util::read_trim(format!("/sys/class/net/{name}/ifindex"))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface not found"))?;
    let raw = unsafe {
        socket(
            AF_PACKET,
            SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
            ETH_P_ALL.to_be() as i32,
        )
    };
    if raw < 0 {
        return Err(last_error());
    }
    let fd = Fd(raw);
    let addr = SockAddrLl {
        family: AF_PACKET as u16,
        protocol: ETH_P_ALL.to_be(),
        ifindex,
        ..SockAddrLl::default()
    };
    let r = unsafe {
        bind(
            fd.0,
            &addr as *const _ as *const c_void,
            size_of::<SockAddrLl>() as u32,
        )
    };
    if r < 0 {
        return Err(last_error());
    }
    Ok(Tap { fd })
}

/// Reads queued packets; only outgoing ones count (what leaves the phone).
fn drain(fd: i32, h4: &mut Hist, h6: &mut Hist) {
    let mut buf = [0u8; 128]; // headers only; the rest is truncated by the kernel
    for _ in 0..4096 {
        let mut from = SockAddrLl::default();
        let mut len = size_of::<SockAddrLl>() as u32;
        let n = unsafe {
            recvfrom(
                fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
                &mut from as *mut _ as *mut c_void,
                &mut len,
            )
        };
        if n <= 0 {
            break;
        }
        if from.pkttype == PACKET_OUTGOING {
            observe(&buf[..n as usize], h4, h6);
        }
    }
}

fn sample(taps: &[Tap], window: Duration, h4: &mut Hist, h6: &mut Hist) {
    if taps.is_empty() {
        thread::sleep(window);
        return;
    }
    let end = Instant::now() + window;
    let mut fds: Vec<PollFd> = taps
        .iter()
        .map(|t| PollFd {
            fd: t.fd.0,
            events: POLLIN,
            revents: 0,
        })
        .collect();
    while Instant::now() < end {
        let ms = end
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(250) as i32;
        let r = unsafe { poll(fds.as_mut_ptr(), fds.len(), ms) };
        if r < 0 {
            if last_error().raw_os_error() == Some(EINTR) {
                continue;
            }
            break;
        }
        for p in fds.iter_mut() {
            if p.revents & POLLIN != 0 {
                drain(p.fd, h4, h6);
            }
            p.revents = 0;
        }
    }
}

fn counters(fw: &Firewall, v6: bool) -> (Option<String>, Vec<RuleCount>) {
    let hook = if v6 { CHAIN6_HOOK } else { CHAIN_HOOK };
    let rules = if v6 {
        fw.out6(&["-S", hook])
    } else {
        fw.out4(&["-S", hook])
    };
    let Some(chain) = active_chain(&rules, hook) else {
        return (None, vec![]);
    };
    let text = if v6 {
        fw.out6(&["-L", chain.as_str(), "-nvx"])
    } else {
        fw.out4(&["-L", chain.as_str(), "-nvx"])
    };
    (Some(chain), parse_counters(&text))
}

fn proc_u8(path: &str) -> u8 {
    util::read_trim(path)
        .and_then(|s| s.parse().ok())
        .unwrap_or(64)
}

/// Runs the verification and returns the process exit code
/// (0 pass, 2 inconclusive, 3 fail; ordinary errors are `Err`).
pub fn run(module: &Path, args: &[String]) -> io::Result<i32> {
    let o = parse_options(args)?;
    Config::validate(&module.join("config.conf"))?;
    let c = Config::load(&module.join("config.conf"));

    let fw = if o.wire_only {
        None
    } else {
        let phase = util::read_trim(util::state_dir().join("phase")).unwrap_or_default();
        if phase != "active" {
            println!(
                "Hotspot rules are not active (phase={}). Turn the hotspot on, connect a client and run verify again, or use --wire-only.\nVERIFY_RESULT=INCONCLUSIVE",
                if phase.is_empty() { "unknown" } else { &phase }
            );
            return Ok(EXIT_INCONCLUSIVE);
        }
        Some(Firewall::select().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no usable iptables (root/SELinux)")
        })?)
    };
    let v6_mode = util::read_trim(util::state_dir().join("ipv6_mode")).unwrap_or_default();
    let backend = util::read_trim(util::state_dir().join("backend")).unwrap_or_default();
    let use_v6_rules = fw.as_ref().is_some_and(|f| f.ip6t.is_some())
        && matches!(v6_mode.as_str(), "normalize" | "block");

    let upstreams = if o.ifaces.is_empty() {
        net::discover(&c).up
    } else {
        o.ifaces.clone()
    };
    let own4 = proc_u8("/proc/sys/net/ipv4/ip_default_ttl");
    let own6 = proc_u8("/proc/sys/net/ipv6/conf/all/hop_limit");

    println!(
        "nfqttl verify {} — {} s window\nConfig: TTL={} IPV6_HL={} backend={} ipv6={}\nPhone default: TTL={own4} HL={own6}",
        util::VERSION,
        o.seconds,
        c.ttl,
        c.ipv6_hl,
        if backend.is_empty() { "unknown" } else { &backend },
        if v6_mode.is_empty() { "unknown" } else { &v6_mode },
    );

    let before4 = fw.as_ref().map(|f| counters(f, false));
    let before6 = if use_v6_rules {
        fw.as_ref().map(|f| counters(f, true))
    } else {
        None
    };

    let mut taps = Vec::new();
    for name in &upstreams {
        match open_tap(name) {
            Ok(t) => taps.push(t),
            Err(e) => println!("Wire sampling unavailable on {name}: {e}"),
        }
    }
    if taps.is_empty() {
        println!("Wire sampling off: result rests on rule counters only.");
    } else {
        println!("Sampling egress on: {}", upstreams.join(" "));
    }
    println!("Generate traffic from a hotspot client now (for example a download).");

    let (mut h4, mut h6) = (Hist::default(), Hist::default());
    sample(&taps, Duration::from_secs(o.seconds), &mut h4, &mut h6);

    let mut hits = None;
    let mut chain_changed = false;
    if let (Some(f), Some((c4, r4))) = (fw.as_ref(), before4.as_ref()) {
        let (a4, ra4) = counters(f, false);
        chain_changed |= a4 != *c4;
        let hits4 = total_hits(r4, &ra4);
        println!(
            "Rule hits IPv4: {hits4} packets{}",
            a4.as_deref()
                .map_or(String::new(), |c| format!(" (chain {c})"))
        );
        let mut total = hits4;
        if let Some((c6, r6)) = before6.as_ref() {
            let (a6, ra6) = counters(f, true);
            chain_changed |= a6 != *c6;
            let hits6 = total_hits(r6, &ra6);
            println!("Rule hits IPv6: {hits6} packets");
            total += hits6;
        }
        hits = Some(total);
    }

    let foreign4 = h4.foreign(&[c.ttl, own4]);
    println!("{}", h4.describe("Wire IPv4 TTL"));
    let wire6_note = if c.ipv6_mode == Ipv6Mode::Pass || v6_mode.starts_with("pass") {
        " (informational; IPv6 is not modified)"
    } else {
        " (informational; CLAT translation can change it)"
    };
    println!("{}{wire6_note}", h6.describe("Wire IPv6 HL"));
    if foreign4 > 0 {
        println!(
            "Foreign IPv4 TTL (not {} or {own4}): {foreign4} packets",
            c.ttl
        );
    }

    let (outcome, reason) = judge(&Evidence {
        hits,
        wire4: h4.total,
        foreign4,
        chain_changed,
    });
    println!(
        "RESULT: {} — {reason}\nVERIFY_RESULT={}",
        outcome.name(),
        outcome.name()
    );
    if outcome == Outcome::Pass {
        println!("Note: this proves the data path, not carrier policy. TTL is only one detection signal.");
    }
    Ok(outcome.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Chain nfqttl_v40a (1 references)\n    pkts      bytes target     prot opt in     out     source               destination\n    1523    2178044 TTL        all  --  wlan2  rmnet_data2  0.0.0.0/0            0.0.0.0/0            TTL set to 64\n       0          0 TTL        all  --  rndis0 rmnet_data2  0.0.0.0/0            0.0.0.0/0            TTL set to 64\n";

    #[test]
    fn parses_real_iptables_counter_rows() {
        let r = parse_counters(SAMPLE);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].pkts, 1523);
        assert_eq!(
            (r[0].input.as_str(), r[0].output.as_str()),
            ("wlan2", "rmnet_data2")
        );
        assert_eq!(r[0].target, "TTL");
        assert_eq!(r[1].pkts, 0);
    }
    #[test]
    fn ignores_headers_and_garbage() {
        assert!(parse_counters("").is_empty());
        assert!(parse_counters(
            "Chain x (1 references)\n pkts bytes target prot opt in out source destination\n"
        )
        .is_empty());
        assert!(parse_counters("1 2 3\nabc def ghi jkl mno pqr stu vwx yz\n").is_empty());
    }
    #[test]
    fn finds_active_chain_only_in_hook_rule() {
        let s = "-N nfqttl_v40h\n-A nfqttl_v40h -j nfqttl_v40b\n";
        assert_eq!(
            active_chain(s, "nfqttl_v40h").as_deref(),
            Some("nfqttl_v40b")
        );
        assert_eq!(active_chain("-N nfqttl_v40h\n", "nfqttl_v40h"), None);
        assert_eq!(
            active_chain("-A FORWARD -j nfqttl_v40h\n", "nfqttl_v40h"),
            None
        );
    }
    #[test]
    fn hits_are_deltas_and_never_underflow() {
        let b = parse_counters(SAMPLE);
        let mut a = b.clone();
        a[0].pkts += 40;
        a[1].pkts += 2;
        assert_eq!(total_hits(&b, &a), 42);
        // chain swapped: counters restarted below the old values
        let fresh = vec![RuleCount {
            pkts: 5,
            ..b[0].clone()
        }];
        assert_eq!(total_hits(&b, &fresh), 0);
        assert_eq!(total_hits(&[], &fresh), 5);
    }
    fn v4(ttl: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[8] = ttl;
        p
    }
    fn v6(hl: u8) -> Vec<u8> {
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[7] = hl;
        p
    }
    #[test]
    fn observe_reads_ttl_and_hop_limit() {
        let (mut a, mut b) = (Hist::default(), Hist::default());
        observe(&v4(64), &mut a, &mut b);
        observe(&v4(63), &mut a, &mut b);
        observe(&v4(63), &mut a, &mut b);
        observe(&v6(64), &mut a, &mut b);
        assert_eq!((a.total, b.total), (3, 1));
        assert_eq!(a.top(2), vec![(63, 2), (64, 1)]);
        assert_eq!(a.foreign(&[64]), 2);
        assert_eq!(a.foreign(&[63, 64]), 0);
    }
    #[test]
    fn observe_survives_short_and_unknown_packets() {
        let (mut a, mut b) = (Hist::default(), Hist::default());
        for n in 0..60 {
            for first in [0x00u8, 0x45, 0x60, 0x4f, 0xff] {
                let mut p = vec![first; n];
                if !p.is_empty() {
                    p[0] = first;
                }
                observe(&p, &mut a, &mut b);
            }
        }
        observe(&[], &mut a, &mut b);
    }
    fn ev(hits: Option<u64>, wire4: u64, foreign4: u64) -> Evidence {
        Evidence {
            hits,
            wire4,
            foreign4,
            chain_changed: false,
        }
    }
    #[test]
    fn pass_needs_rule_hits_and_no_leak() {
        assert_eq!(judge(&ev(Some(500), 500, 0)).0, Outcome::Pass);
        assert_eq!(judge(&ev(Some(500), 0, 0)).0, Outcome::Pass);
        // a handful of odd packets is noise, not a leak
        assert_eq!(judge(&ev(Some(500), 1000, 9)).0, Outcome::Pass);
        assert_eq!(judge(&ev(Some(500), 1000, 40)).0, Outcome::Pass); // 4% < 5%
    }
    #[test]
    fn leak_without_hits_means_bypass() {
        let (o, why) = judge(&ev(Some(0), 400, 300));
        assert_eq!(o, Outcome::Fail);
        assert!(why.contains("bypass"));
    }
    #[test]
    fn leak_with_hits_is_partial_failure() {
        let (o, why) = judge(&ev(Some(100), 400, 200));
        assert_eq!(o, Outcome::Fail);
        assert!(why.contains("share"));
    }
    #[test]
    fn no_traffic_is_inconclusive_not_pass() {
        assert_eq!(judge(&ev(Some(0), 0, 0)).0, Outcome::Inconclusive);
        assert_eq!(judge(&ev(Some(0), 300, 0)).0, Outcome::Inconclusive);
        let mut e = ev(Some(0), 0, 0);
        e.chain_changed = true;
        let (o, why) = judge(&e);
        assert_eq!(o, Outcome::Inconclusive);
        assert!(why.contains("reinstalled"));
    }
    #[test]
    fn wire_only_requires_enough_samples() {
        assert_eq!(judge(&ev(None, 3, 0)).0, Outcome::Inconclusive);
        assert_eq!(judge(&ev(None, 200, 0)).0, Outcome::Pass);
        assert_eq!(judge(&ev(None, 200, 100)).0, Outcome::Fail);
    }
    #[test]
    fn exit_codes_are_distinct() {
        let codes = [Outcome::Pass, Outcome::Inconclusive, Outcome::Fail].map(Outcome::exit_code);
        assert_eq!(codes, [0, 2, 3]);
    }
    #[test]
    fn option_parsing() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let o = parse_options(&a(&[
            "--seconds",
            "5",
            "--iface",
            "lo",
            "--iface",
            "lo",
            "--wire-only",
            "--module-dir",
            "/x",
        ]))
        .unwrap();
        assert_eq!((o.seconds, o.ifaces.len(), o.wire_only), (5, 1, true));
        assert_eq!(parse_options(&[]).unwrap().seconds, DEFAULT_SECONDS);
        for bad in [
            &["--seconds", "1"][..],
            &["--seconds", "61"],
            &["--seconds"],
            &["--seconds", "x"],
            &["--iface"],
            &["--iface", "../etc"],
            &["--iface", "a b"],
            &["--bogus"],
        ] {
            assert!(parse_options(&a(bad)).is_err(), "{bad:?}");
        }
    }
}
