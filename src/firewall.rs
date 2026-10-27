use crate::net::Links;
use crate::util;
use std::path::{Path, PathBuf};

pub const CHAIN_HOOK: &str = "nfqttl_v40h";
pub const CHAIN_A: &str = "nfqttl_v40a";
pub const CHAIN_B: &str = "nfqttl_v40b";
pub const CHAIN6_HOOK: &str = "nfqttl6_v40h";
pub const CHAIN6_A: &str = "nfqttl6_v40a";
pub const CHAIN6_B: &str = "nfqttl6_v40b";
pub const QUEUE_BASE: u16 = 6464;

#[derive(Clone)]
pub struct Firewall {
    pub ipt: PathBuf,
    pub ip6t: Option<PathBuf>,
}
impl Firewall {
    pub fn select() -> Option<Self> {
        let env4 = std::env::var_os("NFQTTL_IPTABLES").map(PathBuf::from);
        let mut c4 = Vec::new();
        if let Some(x) = env4 {
            c4.push(x);
        }
        c4.extend(
            [
                "/system/bin/iptables",
                "/system/bin/iptables-legacy",
                "/system/xbin/iptables-legacy",
                "iptables",
            ]
            .iter()
            .map(|x| PathBuf::from(*x)),
        );
        let ipt = c4.into_iter().find(|p| Self::usable(p, false))?;
        let env6 = std::env::var_os("NFQTTL_IP6TABLES").map(PathBuf::from);
        let mut c6 = Vec::new();
        if let Some(x) = env6 {
            c6.push(x);
        }
        c6.extend(
            [
                "/system/bin/ip6tables",
                "/system/bin/ip6tables-legacy",
                "/system/xbin/ip6tables-legacy",
                "ip6tables",
            ]
            .iter()
            .map(|x| PathBuf::from(*x)),
        );
        let ip6t = c6.into_iter().find(|p| Self::usable(p, true));
        Some(Self { ipt, ip6t })
    }
    fn usable(p: &Path, _v6: bool) -> bool {
        util::output_path(p, &["-w", "2", "-t", "mangle", "-S", "FORWARD"])
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    fn run_path(p: &Path, args: &[String]) -> bool {
        let mut all = vec!["-w".to_string(), "2".into(), "-t".into(), "mangle".into()];
        all.extend_from_slice(args);
        match util::output_path(p, &all) {
            Ok(o) if o.status.success() => true,
            Ok(o) => {
                let noisy = !matches!(
                    args.first().map(String::as_str),
                    Some("-C" | "-N" | "-X" | "-F")
                );
                if noisy {
                    util::write_state(
                        "firewall.last-error",
                        format!(
                            "{} {}: {}",
                            p.display(),
                            args.join(" "),
                            String::from_utf8_lossy(&o.stderr).trim()
                        ),
                    );
                }
                false
            }
            Err(e) => {
                util::write_state("firewall.last-error", format!("{}: {e}", p.display()));
                false
            }
        }
    }
    fn out_path(p: &Path, args: &[&str]) -> String {
        let mut all = vec!["-w", "2", "-t", "mangle"];
        all.extend_from_slice(args);
        util::output_path(p, &all)
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    }
    pub fn ipt(&self, args: &[String]) -> bool {
        Self::run_path(&self.ipt, args)
    }
    pub fn ip6(&self, args: &[String]) -> bool {
        self.ip6t
            .as_ref()
            .map(|p| Self::run_path(p, args))
            .unwrap_or(false)
    }
    pub fn out4(&self, args: &[&str]) -> String {
        Self::out_path(&self.ipt, args)
    }
    pub fn out6(&self, args: &[&str]) -> String {
        self.ip6t
            .as_ref()
            .map(|p| Self::out_path(p, args))
            .unwrap_or_default()
    }
    fn del_jump(&self, v6: bool, parent: &str, target: &str) -> bool {
        for _ in 0..16 {
            let a = vec!["-C".into(), parent.into(), "-j".into(), target.into()];
            let exists = if v6 { self.ip6(&a) } else { self.ipt(&a) };
            if !exists {
                return true;
            }
            let mut d = a;
            d[0] = "-D".into();
            if if v6 { !self.ip6(&d) } else { !self.ipt(&d) } {
                return false;
            }
        }
        false
    }
    pub fn cleanup4(&self) -> bool {
        for c in [
            CHAIN_HOOK,
            "nfqttl_v30h",
            "nfqttl_v30a",
            "nfqttl_v30b",
            "nfqttl_v29a",
            "nfqttl_v29b",
            "nfqttl_fwd",
        ] {
            if !self.del_jump(false, "FORWARD", c) {
                return false;
            }
        }
        for c in [
            CHAIN_HOOK,
            CHAIN_A,
            CHAIN_B,
            "nfqttl_v30h",
            "nfqttl_v30a",
            "nfqttl_v30b",
            "nfqttl_v29a",
            "nfqttl_v29b",
            "nfqttl_fwd",
        ] {
            let _ = self.ipt(&["-F".into(), c.into()]);
        }
        for c in [
            CHAIN_HOOK,
            CHAIN_A,
            CHAIN_B,
            "nfqttl_v30h",
            "nfqttl_v30a",
            "nfqttl_v30b",
            "nfqttl_v29a",
            "nfqttl_v29b",
            "nfqttl_fwd",
        ] {
            let _ = self.ipt(&["-X".into(), c.into()]);
        }
        true
    }
    pub fn cleanup6(&self) -> bool {
        if self.ip6t.is_none() {
            return true;
        }
        for c in [CHAIN6_HOOK, "nfqttl6_v30h", "nfqttl6_v30a", "nfqttl6_v30b"] {
            if !self.del_jump(true, "FORWARD", c) {
                return false;
            }
        }
        for c in [
            CHAIN6_HOOK,
            CHAIN6_A,
            CHAIN6_B,
            "nfqttl6_v30h",
            "nfqttl6_v30a",
            "nfqttl6_v30b",
        ] {
            let _ = self.ip6(&["-F".into(), c.into()]);
        }
        for c in [
            CHAIN6_HOOK,
            CHAIN6_A,
            CHAIN6_B,
            "nfqttl6_v30h",
            "nfqttl6_v30a",
            "nfqttl6_v30b",
        ] {
            let _ = self.ip6(&["-X".into(), c.into()]);
        }
        true
    }
    pub fn cleanup(&self) -> bool {
        self.cleanup4() && self.cleanup6()
    }
    pub fn probe_ttl(&self, ttl: u8) -> bool {
        let p = "nfqttl_tprobe";
        let _ = self.ipt(&["-N".into(), p.into()]);
        let _ = self.ipt(&["-F".into(), p.into()]);
        let ok = self.ipt(&[
            "-A".into(),
            p.into(),
            "-j".into(),
            "TTL".into(),
            "--ttl-set".into(),
            ttl.to_string(),
        ]);
        let _ = self.ipt(&["-F".into(), p.into()]);
        let _ = self.ipt(&["-X".into(), p.into()]);
        ok
    }
    pub fn probe_hl(&self, hl: u8) -> bool {
        if self.ip6t.is_none() {
            return false;
        }
        let p = "nfqttl6_probe";
        let _ = self.ip6(&["-N".into(), p.into()]);
        let _ = self.ip6(&["-F".into(), p.into()]);
        let ok = self.ip6(&[
            "-A".into(),
            p.into(),
            "-j".into(),
            "HL".into(),
            "--hl-set".into(),
            hl.to_string(),
        ]);
        let _ = self.ip6(&["-F".into(), p.into()]);
        let _ = self.ip6(&["-X".into(), p.into()]);
        ok
    }
    pub fn probe_balance(&self, workers: u8) -> bool {
        if workers <= 1 {
            return false;
        }
        let p = "nfqttl_qprobe";
        let _ = self.ipt(&["-N".into(), p.into()]);
        let _ = self.ipt(&["-F".into(), p.into()]);
        let end = QUEUE_BASE + workers as u16 - 1;
        let ok = self.ipt(&[
            "-A".into(),
            p.into(),
            "-j".into(),
            "NFQUEUE".into(),
            "--queue-balance".into(),
            format!("{}:{}", QUEUE_BASE, end),
            "--queue-bypass".into(),
        ]);
        let _ = self.ipt(&["-F".into(), p.into()]);
        let _ = self.ipt(&["-X".into(), p.into()]);
        ok
    }
    fn hook_ok(&self, v6: bool) -> bool {
        let c = if v6 { CHAIN6_HOOK } else { CHAIN_HOOK };
        let s = if v6 {
            self.out6(&["-S", "FORWARD"])
        } else {
            self.out4(&["-S", "FORWARD"])
        };
        let rule = format!("-A FORWARD -j {c}");
        let mut rules = s.lines().filter(|l| l.starts_with("-A "));
        rules.next() == Some(rule.as_str()) && rules.filter(|l| *l == rule).count() == 0
    }
    #[allow(clippy::too_many_arguments)]
    pub fn rules_ok(
        &self,
        v6: bool,
        active: &Option<String>,
        links: &Links,
        kernel: bool,
        workers: u8,
        value: u8,
        mode: &str,
    ) -> bool {
        let Some(c) = active else {
            return false;
        };
        if !self.hook_ok(v6) {
            return false;
        }
        let hook = if v6 { CHAIN6_HOOK } else { CHAIN_HOOK };
        let s = if v6 {
            self.out6(&["-S", hook])
        } else {
            self.out4(&["-S", hook])
        };
        let wanted = format!("-A {hook} -j {c}");
        let actual: Vec<_> = s.lines().filter(|l| l.starts_with("-A ")).collect();
        if actual != vec![wanted.as_str()] {
            return false;
        }
        let mut expected = Vec::new();
        for i in &links.down {
            for o in &links.up {
                if i == o {
                    continue;
                }
                let tail = if v6 {
                    if mode == "normalize" {
                        format!("HL --hl-set {value}")
                    } else {
                        "DROP".into()
                    }
                } else if kernel {
                    format!("TTL --ttl-set {value}")
                } else if workers > 1 {
                    format!(
                        "NFQUEUE --queue-balance {}:{} --queue-bypass",
                        QUEUE_BASE,
                        QUEUE_BASE + workers as u16 - 1
                    )
                } else {
                    format!("NFQUEUE --queue-num {QUEUE_BASE} --queue-bypass")
                };
                expected.push(format!("-A {c} -i {i} -o {o} -j {tail}"));
            }
        }
        let s = if v6 {
            self.out6(&["-S", c])
        } else {
            self.out4(&["-S", c])
        };
        let actual: Vec<_> = s.lines().filter(|l| l.starts_with("-A ")).collect();
        actual == expected
    }
    fn activate(&self, v6: bool, new: &str, active: &Option<String>) -> bool {
        let run = |a: Vec<String>| if v6 { self.ip6(&a) } else { self.ipt(&a) };
        let hook = if v6 { CHAIN6_HOOK } else { CHAIN_HOOK };
        let _ = run(vec!["-N".into(), hook.into()]);
        if (active.is_none()
            || !run(vec![
                "-R".into(),
                hook.into(),
                "1".into(),
                "-j".into(),
                new.into(),
            ]))
            && (!run(vec!["-F".into(), hook.into()])
                || !run(vec!["-A".into(), hook.into(), "-j".into(), new.into()]))
        {
            return false;
        }
        // Remove extra hook entries left by a partial Android table recreation.
        let s = if v6 {
            self.out6(&["-S", hook])
        } else {
            self.out4(&["-S", hook])
        };
        let n = s.lines().filter(|l| l.starts_with("-A ")).count();
        for _ in 1..n {
            if !run(vec!["-D".into(), hook.into(), "2".into()]) {
                return false;
            }
        }
        if !self.hook_ok(v6)
            && (!self.del_jump(v6, "FORWARD", hook)
                || !run(vec![
                    "-I".into(),
                    "FORWARD".into(),
                    "1".into(),
                    "-j".into(),
                    hook.into(),
                ]))
        {
            return false;
        }
        true
    }

    pub fn install4(
        &self,
        links: &Links,
        backend_kernel: bool,
        workers: u8,
        ttl: u8,
        active: &mut Option<String>,
    ) -> bool {
        let new = if active.as_deref() == Some(CHAIN_A) {
            CHAIN_B
        } else {
            CHAIN_A
        };
        let _ = self.ipt(&["-N".into(), new.into()]);
        if !self.ipt(&["-F".into(), new.into()]) {
            return false;
        }
        for i in &links.down {
            for o in &links.up {
                if i == o {
                    continue;
                }
                let mut a = vec![
                    "-A".into(),
                    new.into(),
                    "-i".into(),
                    i.clone(),
                    "-o".into(),
                    o.clone(),
                    "-j".into(),
                ];
                if backend_kernel {
                    a.extend(["TTL".into(), "--ttl-set".into(), ttl.to_string()]);
                } else if workers > 1 {
                    a.extend([
                        "NFQUEUE".into(),
                        "--queue-balance".into(),
                        format!("{}:{}", QUEUE_BASE, QUEUE_BASE + workers as u16 - 1),
                        "--queue-bypass".into(),
                    ]);
                } else {
                    a.extend([
                        "NFQUEUE".into(),
                        "--queue-num".into(),
                        QUEUE_BASE.to_string(),
                        "--queue-bypass".into(),
                    ]);
                }
                if !self.ipt(&a) {
                    return false;
                }
            }
        }
        if !self.activate(false, new, active) {
            return false;
        }
        if let Some(old) = active.take() {
            let _ = self.ipt(&["-F".into(), old]);
        }
        *active = Some(new.into());
        true
    }

    pub fn install6(&self, links: &Links, mode: &str, hl: u8, active: &mut Option<String>) -> bool {
        if mode.starts_with("pass") {
            let _ = self.cleanup6();
            *active = None;
            return true;
        }
        if self.ip6t.is_none() {
            return mode == "pass-no-ip6tables";
        }
        let new = if active.as_deref() == Some(CHAIN6_A) {
            CHAIN6_B
        } else {
            CHAIN6_A
        };
        let _ = self.ip6(&["-N".into(), new.into()]);
        if !self.ip6(&["-F".into(), new.into()]) {
            return false;
        }
        for i in &links.down {
            for o in &links.up {
                if i == o {
                    continue;
                }
                let mut a = vec![
                    "-A".into(),
                    new.into(),
                    "-i".into(),
                    i.clone(),
                    "-o".into(),
                    o.clone(),
                    "-j".into(),
                ];
                if mode == "normalize" {
                    a.extend(["HL".into(), "--hl-set".into(), hl.to_string()]);
                } else {
                    a.push("DROP".into());
                }
                if !self.ip6(&a) {
                    return false;
                }
            }
        }
        if !self.activate(true, new, active) {
            return false;
        }
        if let Some(old) = active.take() {
            let _ = self.ip6(&["-F".into(), old]);
        }
        *active = Some(new.into());
        true
    }
}
