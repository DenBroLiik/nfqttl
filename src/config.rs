use std::fs;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Auto,
    Kernel,
    Nfqueue,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6Mode {
    Auto,
    Normalize,
    Block,
    Pass,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub ttl: u8,
    pub backend: Backend,
    pub workers: u8,
    pub downstreams: Vec<String>,
    pub upstreams: Vec<String>,
    pub disable_offload: bool,
    pub ipv6_mode: Ipv6Mode,
    pub ipv6_hl: u8,
    pub max_failures: u8,
    pub cooldown: u64,
    pub queue_maxlen: u32,
    pub rcvbuf_mb: u32,
    pub max_backlog: u64,
    pub stall_limit: u8,
    pub watchdog_ms: i32,
    pub idle_ms: i32,
    pub rescan_ms: u64,
    pub check_ms: u64,
    pub gso: bool,
    pub sqm_up_kbit: u32,
    pub sqm_down_kbit: u32,
    pub sqm_up_iface: String,
    pub sqm_down_iface: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ttl: 64,
            backend: Backend::Auto,
            workers: 1,
            downstreams: vec![],
            upstreams: vec![],
            disable_offload: true,
            ipv6_mode: Ipv6Mode::Auto,
            ipv6_hl: 64,
            max_failures: 6,
            cooldown: 1,
            queue_maxlen: 4096,
            rcvbuf_mb: 8,
            max_backlog: 3072,
            stall_limit: 3,
            watchdog_ms: 500,
            idle_ms: 10000,
            rescan_ms: 10000,
            check_ms: 5000,
            gso: false,
            sqm_up_kbit: 0,
            sqm_down_kbit: 0,
            sqm_up_iface: String::new(),
            sqm_down_iface: String::new(),
        }
    }
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}
fn int<T: std::str::FromStr + Copy>(s: &str, default: T) -> T {
    s.parse().ok().unwrap_or(default)
}

impl Config {
    pub fn load(path: &Path) -> Self {
        let mut c = Self::default();
        let Ok(text) = fs::read_to_string(path) else {
            return c;
        };
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let v = unquote(v);
            match k.trim() {
                "TTL" => {
                    let n = int(v, 64u16);
                    if (1..=255).contains(&n) {
                        c.ttl = n as u8;
                    }
                }
                "BACKEND" => {
                    c.backend = match v {
                        "kernel" => Backend::Kernel,
                        "nfqueue" => Backend::Nfqueue,
                        _ => Backend::Auto,
                    }
                }
                "WORKERS" => {
                    let n = int(v, 1u16);
                    if (1..=8).contains(&n) {
                        c.workers = n as u8;
                    }
                }
                "DOWNSTREAMS" => {
                    c.downstreams = v
                        .split_whitespace()
                        .filter(|x| valid_iface(x))
                        .map(str::to_string)
                        .collect()
                }
                "UPSTREAMS" => {
                    c.upstreams = v
                        .split_whitespace()
                        .filter(|x| valid_iface(x))
                        .map(str::to_string)
                        .collect()
                }
                "DISABLE_OFFLOAD" => c.disable_offload = v == "1" || v.eq_ignore_ascii_case("true"),
                "IPV6_MODE" => {
                    c.ipv6_mode = match v {
                        "normalize" => Ipv6Mode::Normalize,
                        "block" => Ipv6Mode::Block,
                        "pass" => Ipv6Mode::Pass,
                        _ => Ipv6Mode::Auto,
                    }
                }
                "IPV6_HL" => {
                    let n = int(v, 64u16);
                    if (1..=255).contains(&n) {
                        c.ipv6_hl = n as u8;
                    }
                }
                "MAX_FAILURES" => {
                    let n = int(v, 6u16);
                    if (1..=20).contains(&n) {
                        c.max_failures = n as u8;
                    }
                }
                "COOLDOWN" => {
                    let n = int(v, 1u64);
                    if (0..=60).contains(&n) {
                        c.cooldown = n;
                    }
                }
                "QUEUE_MAXLEN" => {
                    let n = int(v, 4096u32);
                    if (256..=32768).contains(&n) {
                        c.queue_maxlen = n;
                    }
                }
                "RCVBUF_MB" => {
                    let n = int(v, 8u32);
                    if (1..=64).contains(&n) {
                        c.rcvbuf_mb = n;
                    }
                }
                "MAX_BACKLOG" => {
                    let n = int(v, 3072u64);
                    if (32..=32768).contains(&n) {
                        c.max_backlog = n;
                    }
                }
                "STALL_LIMIT" => {
                    let n = int(v, 3u16);
                    if (2..=20).contains(&n) {
                        c.stall_limit = n as u8;
                    }
                }
                "WATCHDOG_MS" => {
                    let n = int(v, 500i32);
                    if (100..=5000).contains(&n) {
                        c.watchdog_ms = n;
                    }
                }
                "IDLE_MS" => c.idle_ms = int(v, 10000i32).clamp(1000, 60000),
                "RESCAN_MS" => c.rescan_ms = int(v, 10000u64).clamp(1000, 60000),
                "CHECK_MS" => c.check_ms = int(v, 5000u64).clamp(1000, 60000),
                "SQM_UP_KBIT" => c.sqm_up_kbit = int(v, 0u32),
                "SQM_DOWN_KBIT" => c.sqm_down_kbit = int(v, 0u32),
                "SQM_UP_IFACE" => c.sqm_up_iface = v.to_owned(),
                "SQM_DOWN_IFACE" => c.sqm_down_iface = v.to_owned(),
                "GSO" => c.gso = v == "1" || v.eq_ignore_ascii_case("true"),
                _ => {}
            }
        }
        if c.max_backlog > c.queue_maxlen as u64 {
            c.max_backlog = c.queue_maxlen as u64;
        }
        c
    }
}

pub fn valid_iface(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn iface_validation() {
        assert!(valid_iface("rmnet_data2"));
        assert!(valid_iface("wlan0"));
        assert!(!valid_iface("x;reboot"));
    }
}

impl Config {
    pub fn validate(path: &Path) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind};
        let text = fs::read_to_string(path)?;
        let mut keys = std::collections::BTreeSet::new();
        let mut down = Vec::new();
        let mut up = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let err = |m: &str| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("config line {}: {m}", i + 1),
                )
            };
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| err("expected KEY=VALUE"))?;
            let k = k.trim();
            let v = unquote(v);
            if !keys.insert(k) {
                return Err(err("duplicate setting"));
            }
            let bounds = match k {
                "TTL" | "IPV6_HL" => Some((1, 255)),
                "SQM_UP_KBIT" | "SQM_DOWN_KBIT" => Some((0, 1_000_000)),
                "WORKERS" => Some((1, 8)),
                "MAX_FAILURES" => Some((1, 20)),
                "COOLDOWN" => Some((0, 60)),
                "QUEUE_MAXLEN" => Some((256, 32768)),
                "RCVBUF_MB" => Some((1, 64)),
                "MAX_BACKLOG" => Some((32, 32768)),
                "STALL_LIMIT" => Some((2, 20)),
                "WATCHDOG_MS" => Some((100, 5000)),
                "IDLE_MS" | "RESCAN_MS" | "CHECK_MS" => Some((1000, 60000)),
                _ => None,
            };
            if let Some((min, max)) = bounds {
                let n = v.parse::<u64>().map_err(|_| err("expected integer"))?;
                if !(min..=max).contains(&n) {
                    return Err(err(&format!("{k} must be {min}..{max}")));
                }
                continue;
            }
            let valid = match k {
                "SQM_UP_IFACE" | "SQM_DOWN_IFACE" => v.is_empty() || valid_iface(v),
                "BACKEND" => matches!(v, "auto" | "kernel" | "nfqueue"),
                "IPV6_MODE" => matches!(v, "auto" | "normalize" | "block" | "pass"),
                "DISABLE_OFFLOAD" | "GSO" => matches!(v, "0" | "1" | "true" | "false"),
                "DOWNSTREAMS" | "UPSTREAMS" => {
                    let a: Vec<_> = v.split_whitespace().collect();
                    if k == "DOWNSTREAMS" {
                        down = a.clone();
                    } else {
                        up = a.clone();
                    }
                    a.iter().all(|s| valid_iface(s))
                }
                _ => false,
            };
            if !valid {
                return Err(err(&format!("unknown setting or invalid value: {k}")));
            }
        }
        if down.iter().any(|s| up.contains(s)) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "DOWNSTREAMS and UPSTREAMS overlap",
            ));
        }
        let c = Self::load(path);
        for (rate, iface) in [
            (c.sqm_up_kbit, &c.sqm_up_iface),
            (c.sqm_down_kbit, &c.sqm_down_iface),
        ] {
            if rate > 0 && (rate < 100 || iface.is_empty()) {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "SQM: positive rate must be 100..1000000 kbit/s with an explicit interface",
                ));
            }
        }
        if c.sqm_up_kbit > 0 || c.sqm_down_kbit > 0 {
            if !c.disable_offload {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "SQM requires DISABLE_OFFLOAD=1",
                ));
            }
            if c.sqm_up_iface == c.sqm_down_iface && c.sqm_up_kbit > 0 && c.sqm_down_kbit > 0 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "SQM interfaces must differ",
                ));
            }
            if c.sqm_up_iface.starts_with("v4-") || c.sqm_up_iface.starts_with("clat") {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "SQM upload: use the underlying physical interface, not CLAT",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    #[test]
    fn reject_bad_config() {
        let dir = std::env::temp_dir().join(format!("nfqttl-config-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.conf");
        for s in [
            "TTL=0\n",
            "TTL=256\n",
            "TTL=64\nTTL=65\n",
            "WORKERS=9\n",
            "BACKEND=bogus\n",
            "GSO=yes\n",
            "DOWNSTREAMS=\"wlan2;reboot\"\n",
            "DOWNSTREAMS=wlan2\nUPSTREAMS=wlan2\n",
            "WATCHDOG_MS=-1\n",
            "UNKNOWN=1\n",
            "SQM_UP_KBIT=99\nSQM_UP_IFACE=rmnet_data2\n",
            "SQM_UP_KBIT=8000\n",
            "SQM_UP_KBIT=8000\nSQM_UP_IFACE=rmnet_data2\nDISABLE_OFFLOAD=0\n",
            "SQM_UP_KBIT=8000\nSQM_UP_IFACE=v4-rmnet_data2\n",
        ] {
            fs::write(&p, s).unwrap();
            assert!(Config::validate(&p).is_err(), "accepted: {s}");
        }
        fs::write(&p,"TTL=65\nWORKERS=2\nGSO=0\nBACKEND=kernel\nDOWNSTREAMS=\"wlan2 rndis0\"\nIPV6_MODE=normalize\n").unwrap();
        Config::validate(&p).unwrap();
        let c = Config::load(&p);
        assert_eq!(c.ttl, 65);
        assert_eq!(c.workers, 2);
        assert!(!c.gso);
        assert_eq!(c.downstreams, vec!["wlan2", "rndis0"]);
        fs::write(&p,"SQM_UP_KBIT=8000\nSQM_UP_IFACE=rmnet_data2\nSQM_DOWN_KBIT=42500\nSQM_DOWN_IFACE=wlan2\nDISABLE_OFFLOAD=1\n").unwrap();
        Config::validate(&p).unwrap();
        let c = Config::load(&p);
        assert_eq!(c.sqm_up_kbit, 8000);
        assert_eq!(c.sqm_down_iface, "wlan2");
        let _ = fs::remove_dir_all(dir);
    }
}
