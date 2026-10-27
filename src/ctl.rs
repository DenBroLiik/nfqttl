use crate::config::Config;
use crate::firewall::{Firewall, CHAIN6_HOOK, CHAIN_HOOK, QUEUE_BASE};
use crate::net;
use crate::offload;
use crate::sys::*;
use crate::util;
use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn daemon_pid() -> Option<i32> {
    util::read_trim(util::state_dir().join("lock/pid")).and_then(|x| x.parse().ok())
}

pub fn status(module: &Path) -> io::Result<()> {
    if let Ok(s) = fs::read_to_string(module.join("module.prop")) {
        print!("{s}");
    }
    let live = daemon_pid().filter(|pid| util::owned_pid(*pid, "daemon"));
    println!(
        "Running: {}\nPhase: {}",
        live.is_some(),
        util::read_trim(util::state_dir().join("phase")).unwrap_or_else(|| "unknown".into())
    );
    println!(
        "Backend:\n{}",
        util::read_trim(util::state_dir().join("backend")).unwrap_or_default()
    );
    let workers = util::read_trim(util::state_dir().join("workers")).unwrap_or_else(|| "1".into());
    println!("NFQUEUE workers:\n{workers}");
    println!(
        "IPv6 mode:\n{}",
        util::read_trim(util::state_dir().join("ipv6_mode")).unwrap_or_default()
    );
    println!(
        "Supervisor:\n{}",
        live.map(|x| x.to_string()).unwrap_or_default()
    );
    println!("Worker pids:");
    if let Ok(rd) = fs::read_dir(util::state_dir()) {
        let mut v = vec![];
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with("worker.") && n.ends_with(".pid") {
                v.push((n, e.path()));
            }
        }
        v.sort_by(|a, b| a.0.cmp(&b.0));
        for (n, p) in v {
            let q = n.trim_start_matches("worker.").trim_end_matches(".pid");
            println!("{q}: {}", util::read_trim(p).unwrap_or_default());
        }
    }
    println!(
        "Paused:\n{}",
        if util::state_dir().join("paused").exists() {
            "yes"
        } else {
            "no"
        }
    );
    if let Some(x) = util::read_trim(util::state_dir().join("interfaces")) {
        println!("{x}");
    }
    if let Some(fw) = Firewall::select() {
        let count = workers.parse::<u16>().unwrap_or(0).min(8);
        println!("Queue (queue, pid, length, kernel drops, userspace drops, sequence):");
        if let Ok(s) = fs::read_to_string("/proc/net/netfilter/nfnetlink_queue") {
            for line in s.lines() {
                let q = line
                    .split_whitespace()
                    .next()
                    .and_then(|x| x.parse::<u16>().ok())
                    .unwrap_or(0);
                if q >= QUEUE_BASE && q < QUEUE_BASE + count {
                    println!("{line}");
                }
            }
        }
        println!(
            "IPv4 hook counters:\n{}",
            fw.out4(&["-L", CHAIN_HOOK, "-nvx"])
        );
        if fw.ip6t.is_some() {
            println!(
                "IPv6 hook counters:\n{}",
                fw.out6(&["-L", CHAIN6_HOOK, "-nvx"])
            );
        }
    }
    for name in [
        "sqm.status",
        "queue.stats",
        "last-recovery",
        "last-error",
        "firewall.last-error",
    ] {
        if let Some(s) = util::read_trim(util::state_dir().join(name)) {
            println!("{name}: {s}");
        }
    }
    for (cmd, args) in [
        ("settings", vec!["get", "global", "tether_offload_disabled"]),
        (
            "device_config",
            vec!["get", "connectivity", "tether_enable_bpf_offload"],
        ),
        (
            "device_config",
            vec!["get", "tethering", "tether_enable_bpf_offload"],
        ),
    ] {
        println!(
            "{}: {}",
            args.join(" "),
            util::text(cmd, &args).unwrap_or_else(|| "unavailable".into())
        );
    }
    let tail = util::tail_lines(&util::state_dir().join("service.log"), 30);
    if !tail.is_empty() {
        println!("{tail}");
    }
    Ok(())
}

fn stop_orphans() {
    if let Ok(rd) = fs::read_dir(util::state_dir()) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with("worker.") && n.ends_with(".pid") {
                if let Some(pid) = util::read_trim(e.path()).and_then(|s| s.parse::<i32>().ok()) {
                    if util::owned_pid(pid, "worker") {
                        unsafe {
                            kill(pid, SIGTERM);
                        }
                    }
                }
            }
        }
    }
}
pub fn stop() -> io::Result<()> {
    util::ensure_state()?;
    fs::write(util::state_dir().join("paused"), b"")?;
    if let Some(pid) = daemon_pid().filter(|pid| util::owned_pid(*pid, "daemon")) {
        unsafe {
            kill(pid, SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(45);
        while Instant::now() < deadline && util::owned_pid(pid, "daemon") {
            thread::sleep(Duration::from_millis(100));
        }
        if util::owned_pid(pid, "daemon") {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "supervisor still stopping; inspect service.log",
            ));
        }
    }
    // Hook removal precedes worker termination so no new packets are queued.
    if let Some(fw) = Firewall::select() {
        if !fw.cleanup() {
            return Err(io::Error::other("firewall cleanup incomplete"));
        }
    }
    stop_orphans();
    let sqm_result = crate::qos::cleanup();
    offload::restore();
    sqm_result?;
    util::write_state("phase", "stopped");
    println!("Stopped. Restart hotspot to re-evaluate Android offload.");
    Ok(())
}
pub fn start(module: &Path) -> io::Result<()> {
    if module.join("disable").exists() || module.join("remove").exists() {
        return Err(io::Error::other("Enable module in Magisk/KernelSU first"));
    }
    Config::validate(&module.join("config.conf"))?;
    util::ensure_state()?;
    if daemon_pid().is_some_and(|pid| util::owned_pid(pid, "daemon")) {
        println!("Already running");
        return Ok(());
    }
    let _ = fs::remove_file(util::state_dir().join("paused"));
    util::remove_state("last-error");
    let exe = std::env::current_exe()?;
    Command::new(exe)
        .arg("daemon")
        .arg("--module-dir")
        .arg(module)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    println!("Start requested. Check status/service.log.");
    Ok(())
}
pub fn restart(module: &Path) -> io::Result<()> {
    Config::validate(&module.join("config.conf"))?;
    stop()?;
    start(module)
}
pub fn toggle(module: &Path) -> io::Result<()> {
    if daemon_pid().is_some_and(|pid| util::owned_pid(pid, "daemon")) {
        stop()
    } else {
        start(module)
    }
}
pub fn doctor(module: &Path) -> io::Result<()> {
    Config::validate(&module.join("config.conf"))?;
    let c = Config::load(&module.join("config.conf"));
    println!(
        "Config: OK\nDevice: {}\nKernel: {}",
        util::text("getprop", &["ro.product.device"]).unwrap_or_default(),
        util::text("uname", &["-a"]).unwrap_or_default()
    );
    let fw = Firewall::select().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no usable iptables (root/SELinux/mangle)",
        )
    })?;
    println!(
        "iptables: {}\nip6tables: {}",
        fw.ipt.display(),
        fw.ip6t
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "unavailable".into())
    );
    println!(
        "Kernel TTL: {}\nKernel IPv6 HL: {}\nNFQUEUE balance: {}",
        fw.probe_ttl(c.ttl),
        fw.probe_hl(c.ipv6_hl),
        fw.probe_balance(c.workers)
    );
    let l = net::discover(&c);
    println!(
        "Detected downstream: {}\nDetected upstream: {}\nTether candidate present: {}",
        l.down.join(" "),
        l.up.join(" "),
        l.active()
    );
    if let Err(e) = crate::qos::status() {
        println!("Qdisc inspection unavailable: {e}");
    }
    println!("Offload must be disabled before hotspot restart. Verify dumpsys tethering; enabled config values alone do not prove packets take the slow path.");
    Ok(())
}

pub fn control_lock() -> io::Result<fs::File> {
    use std::os::fd::AsRawFd;
    util::ensure_state()?;
    let f = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(util::state_dir().join("control.flock"))?;
    if unsafe { flock(f.as_raw_fd(), LOCK_EX | LOCK_NB) } < 0 {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "another control operation is running",
        ));
    }
    Ok(f)
}
pub fn snapshot(module: &Path) -> io::Result<()> {
    Config::validate(&module.join("config.conf"))?;
    let c = Config::load(&module.join("config.conf"));
    println!("VERSION=4.3.0-eclipse\nTTL={}\nIPV6_HL={}\nBACKEND={}\nIPV6_MODE={}\nWORKERS={}\nDISABLE_OFFLOAD={}\nGSO={}",c.ttl,c.ipv6_hl,format!("{:?}",c.backend).to_lowercase(),format!("{:?}",c.ipv6_mode).to_lowercase(),c.workers,c.disable_offload as u8,c.gso as u8);
    println!(
        "SQM_UP_KBIT={}\nSQM_DOWN_KBIT={}\nSQM_UP_IFACE={}\nSQM_DOWN_IFACE={}",
        c.sqm_up_kbit, c.sqm_down_kbit, c.sqm_up_iface, c.sqm_down_iface
    );
    println!(
        "RUNNING={}\nPAUSED={}",
        daemon_pid().is_some_and(|p| util::owned_pid(p, "daemon")) as u8,
        util::state_dir().join("paused").exists() as u8
    );
    for n in [
        "phase",
        "backend",
        "workers",
        "ipv6_mode",
        "interfaces",
        "sqm.status",
        "queue.stats",
        "last-error",
        "last-recovery",
    ] {
        println!(
            "STATE_{}={}",
            n.replace(['.', '-'], "_").to_uppercase(),
            util::read_trim(util::state_dir().join(n)).unwrap_or_default()
        );
    }
    Ok(())
}
pub fn configure(module: &Path, settings: &[String]) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = module.join("config.conf");
    let old = fs::read_to_string(&path)?;
    let mut entries = std::collections::BTreeMap::new();
    for s in settings {
        let Some((k, v)) = s.split_once('=') else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "use KEY=VALUE"));
        };
        if k.is_empty()
            || !k
                .bytes()
                .all(|x| x.is_ascii_uppercase() || x == b'_' || x.is_ascii_digit())
            || v.contains(['\n', '\r', '\0'])
            || entries.insert(k, v).is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid or duplicate setting",
            ));
        }
    }
    if entries.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no settings supplied",
        ));
    }
    let mut text = String::new();
    for line in old.lines() {
        if let Some((key, _)) = line.split_once('=') {
            if let Some(v) = entries.remove(key.trim()) {
                text.push_str(&format!("{}={v}\n", key.trim()));
                continue;
            }
        }
        text.push_str(line);
        text.push('\n');
    }
    for (k, v) in entries {
        text.push_str(&format!("{k}={v}\n"));
    }
    let temp = module.join("config.conf.tmp");
    fs::write(&temp, text)?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))?;
    if let Err(e) = Config::validate(&temp) {
        let _ = fs::remove_file(temp);
        return Err(e);
    }
    let running = daemon_pid().is_some_and(|p| util::owned_pid(p, "daemon"));
    if running {
        stop()?;
    }
    fs::write(module.join("config.conf.bak"), old)?;
    fs::rename(temp, path)?;
    if running {
        start(module)?;
    }
    println!("Configuration saved; previous version is config.conf.bak.");
    Ok(())
}
