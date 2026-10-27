use crate::config::{Backend, Config, Ipv6Mode};
use crate::firewall::{Firewall, QUEUE_BASE};
use crate::net::{self, RouteWatcher};
use crate::offload;
use crate::sys::*;
use crate::util;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_signal(_: i32) {
    STOP.store(true, Ordering::SeqCst);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EffectiveBackend {
    Kernel,
    Nfqueue,
}
impl EffectiveBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Nfqueue => "nfqueue",
        }
    }
}

struct Worker {
    queue: u16,
    child: Child,
}
struct Workers {
    items: Vec<Worker>,
    exe: PathBuf,
    module_dir: PathBuf,
    ttl: u8,
    queue_maxlen: u32,
    rcvbuf_mb: u32,
    gso: bool,
}
impl Workers {
    fn new(
        exe: PathBuf,
        module_dir: PathBuf,
        ttl: u8,
        queue_maxlen: u32,
        rcvbuf_mb: u32,
        gso: bool,
    ) -> Self {
        Self {
            items: vec![],
            exe,
            module_dir,
            ttl,
            queue_maxlen,
            rcvbuf_mb,
            gso,
        }
    }
    fn queue_owner(q: u16) -> Option<i32> {
        let s = fs::read_to_string("/proc/net/netfilter/nfnetlink_queue").ok()?;
        for line in s.lines() {
            let w: Vec<_> = line.split_whitespace().collect();
            if w.len() >= 2 && w[0].parse::<u16>().ok() == Some(q) {
                return w[1].parse().ok();
            }
        }
        None
    }
    fn stop(&mut self) {
        for w in &mut self.items {
            let pid = w.child.id() as i32;
            unsafe {
                kill(pid, SIGTERM);
            }
        }
        if !self.items.is_empty() {
            thread::sleep(Duration::from_millis(100));
        }
        for w in &mut self.items {
            if w.child.try_wait().ok().flatten().is_none() {
                let _ = w.child.kill();
            }
            let _ = w.child.wait();
            util::remove_state(&format!("worker.{}.pid", w.queue));
        }
        self.items.clear();
        util::remove_state("worker.pid");
    }
    fn healthy(&mut self, count: u8) -> bool {
        if self.items.len() != count as usize {
            return false;
        }
        for w in &mut self.items {
            if w.child.try_wait().ok().flatten().is_some() {
                return false;
            }
            if Self::queue_owner(w.queue) != Some(w.child.id() as i32) {
                return false;
            }
        }
        true
    }
    fn start(&mut self, count: u8) -> bool {
        self.stop();
        for i in 0..count {
            let q = QUEUE_BASE + i as u16;
            if let Some(owner) = Self::queue_owner(q) {
                util::log(&format!("ERROR: queue {q} already owned by pid={owner}"));
                return false;
            }
        }
        for i in 0..count {
            let q = QUEUE_BASE + i as u16;
            let log = util::state_dir().join(format!("worker.{q}.log"));
            let _ = fs::rename(&log, util::state_dir().join(format!("worker.{q}.log.1")));
            let out = match OpenOptions::new().create(true).append(true).open(&log) {
                Ok(x) => x,
                Err(e) => {
                    util::log(&format!("ERROR: worker log: {e}"));
                    self.stop();
                    return false;
                }
            };
            let err = match out.try_clone() {
                Ok(x) => x,
                Err(_) => {
                    self.stop();
                    return false;
                }
            };
            let child = Command::new(&self.exe)
                .arg("worker")
                .arg("--queue")
                .arg(q.to_string())
                .arg("--ttl")
                .arg(self.ttl.to_string())
                .arg("--queue-maxlen")
                .arg(self.queue_maxlen.to_string())
                .arg("--rcvbuf-mb")
                .arg(self.rcvbuf_mb.to_string())
                .arg("--gso")
                .arg(if self.gso { "1" } else { "0" })
                .arg("--module-dir")
                .arg(&self.module_dir)
                .stdout(Stdio::from(out))
                .stderr(Stdio::from(err))
                .spawn();
            let Ok(child) = child else {
                self.stop();
                return false;
            };
            util::write_state(&format!("worker.{q}.pid"), child.id().to_string());
            if i == 0 {
                util::write_state("worker.pid", child.id().to_string());
            }
            self.items.push(Worker { queue: q, child });
        }
        for _ in 0..80 {
            if STOP.load(Ordering::Relaxed) {
                self.stop();
                return false;
            }
            if self.healthy(count) {
                let ready = self.items.iter().all(|w| {
                    util::read_trim(util::state_dir().join(format!("worker.{}.log", w.queue)))
                        .map(|x| x.contains("READY "))
                        .unwrap_or(false)
                });
                if ready {
                    return true;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        false
    }
}
impl Drop for Workers {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Default, Clone, Debug)]
struct QStats {
    rows: u8,
    len: u64,
    kdrops: u64,
    udrops: u64,
    entries: Vec<(u16, u64, u64)>,
}
fn queue_stats(count: u8) -> QStats {
    let mut r = QStats::default();
    let end = QUEUE_BASE + count as u16 - 1;
    if let Ok(s) = fs::read_to_string("/proc/net/netfilter/nfnetlink_queue") {
        for line in s.lines() {
            let w: Vec<_> = line.split_whitespace().collect();
            if w.len() != 9 && w.len() < 8 {
                continue;
            }
            let Ok(q) = w[0].parse::<u16>() else {
                continue;
            };
            if q < QUEUE_BASE || q > end {
                continue;
            }
            r.rows += 1;
            let len = w.get(2).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
            let kd = w.get(5).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
            let ud = w.get(6).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
            let seq = w.get(7).copied().unwrap_or("0");
            r.len += len;
            r.kdrops += kd;
            r.udrops += ud;
            r.entries.push((q, len, seq.parse().unwrap_or(0)));
        }
    }
    r
}

fn stall_sample(
    previous: &mut std::collections::BTreeMap<u16, (u64, u64, u8)>,
    sample: &QStats,
) -> u8 {
    previous.retain(|q, _| sample.entries.iter().any(|(n, _, _)| n == q));
    let mut worst = 0;
    for &(q, len, seq) in &sample.entries {
        let n = match previous.get(&q) {
            Some(&(old_len, old_seq, n)) if len > 0 && len == old_len && seq == old_seq => {
                n.saturating_add(1)
            }
            _ => 0,
        };
        previous.insert(q, (len, seq, n));
        worst = worst.max(n);
    }
    worst
}

fn boot_wait() {
    for _ in 0..120 {
        if STOP.load(Ordering::Relaxed)
            || util::text("getprop", &["sys.boot_completed"]).as_deref() == Some("1")
        {
            return;
        }
        thread::sleep(Duration::from_secs(1));
    }
}
fn acquire_lock() -> io::Result<(PathBuf, fs::File)> {
    util::ensure_state()?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(util::state_dir().join("daemon.flock"))?;
    if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } < 0 {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "daemon already running",
        ));
    }
    let lock = util::state_dir().join("lock");
    fs::create_dir_all(&lock)?;
    fs::write(lock.join("pid"), std::process::id().to_string())?;
    Ok((lock, file))
}
fn release_lock(lock: &Path) {
    let _ = fs::remove_file(lock.join("pid"));
    let _ = fs::remove_dir(lock);
}

fn choose_v6(fw: &Firewall, c: &Config) -> io::Result<&'static str> {
    match c.ipv6_mode {
        Ipv6Mode::Pass => Ok("pass"),
        Ipv6Mode::Block => {
            if fw.ip6t.is_some() {
                Ok("block")
            } else {
                util::log("WARNING: ip6tables unavailable; IPv6 block cannot be enforced");
                Ok("pass-no-ip6tables")
            }
        }
        Ipv6Mode::Normalize => {
            if fw.ip6t.is_none() {
                Err(io::Error::other(
                    "IPv6 normalization requested but ip6tables unavailable",
                ))
            } else if fw.probe_hl(c.ipv6_hl) {
                Ok("normalize")
            } else {
                Err(io::Error::other("IPv6 HL target unavailable"))
            }
        }
        Ipv6Mode::Auto => {
            if fw.ip6t.is_none() {
                util::log("WARNING: ip6tables unavailable; forwarded IPv6 cannot be normalized or blocked");
                Ok("pass-no-ip6tables")
            } else if fw.probe_hl(c.ipv6_hl) {
                Ok("normalize")
            } else {
                Ok("block")
            }
        }
    }
}

pub fn run(module_dir: &Path) -> io::Result<()> {
    STOP.store(false, Ordering::SeqCst);
    unsafe {
        signal(SIGTERM, on_signal as *const () as usize);
        signal(SIGINT, on_signal as *const () as usize);
    }
    let (lock, _guard) = match acquire_lock() {
        Ok(x) => x,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut result = run_inner(module_dir);
    if let Err(e) = crate::qos::cleanup() {
        util::log(&format!("SQM cleanup failed: {e}"));
        if result.is_ok() {
            result = Err(e);
        }
    }
    if let Err(e) = &result {
        util::log(&format!("ERROR: {e}"));
        util::write_state("phase", "error");
        util::write_state("last-error", e.to_string());
    }
    release_lock(&lock);
    result
}

fn run_inner(module_dir: &Path) -> io::Result<()> {
    if module_dir.join("disable").exists()
        || module_dir.join("remove").exists()
        || util::state_dir().join("paused").exists()
    {
        util::write_state("phase", "stopped");
        return Ok(());
    }
    util::write_state("phase", "boot-wait");
    boot_wait();
    if STOP.load(Ordering::Relaxed) {
        util::write_state("phase", "stopped");
        return Ok(());
    }
    Config::validate(&module_dir.join("config.conf"))?;
    let fw = Firewall::select().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "usable Android iptables not found")
    })?;
    if !fw.cleanup() {
        return Err(io::Error::other("initial firewall cleanup failed"));
    }
    let c = Config::load(&module_dir.join("config.conf"));
    util::log(&format!(
        "v{} starting; requested={:?} ttl={} workers={} ipv6={:?}",
        util::VERSION,
        c.backend,
        c.ttl,
        c.workers,
        c.ipv6_mode
    ));
    let backend = match c.backend {
        Backend::Nfqueue => EffectiveBackend::Nfqueue,
        Backend::Kernel => {
            if fw.probe_ttl(c.ttl) {
                EffectiveBackend::Kernel
            } else {
                return Err(io::Error::other("kernel TTL target unavailable"));
            }
        }
        Backend::Auto => {
            if fw.probe_ttl(c.ttl) {
                EffectiveBackend::Kernel
            } else {
                EffectiveBackend::Nfqueue
            }
        }
    };
    let mut active_workers = if backend == EffectiveBackend::Nfqueue && fw.probe_balance(c.workers)
    {
        c.workers
    } else {
        1
    };
    let v6 = choose_v6(&fw, &c)?;
    let exe = std::env::current_exe()?;
    util::write_state("backend", backend.as_str());
    util::write_state(
        "workers",
        if backend == EffectiveBackend::Kernel {
            "0".into()
        } else {
            active_workers.to_string()
        },
    );
    util::write_state("ipv6_mode", v6);
    if c.disable_offload {
        offload::apply(true);
    } else {
        offload::restore();
    }
    util::log(&format!(
        "backend={} workers={} ipv6={v6}; restart hotspot if already active",
        backend.as_str(),
        active_workers
    ));
    let mut workers = Workers::new(
        exe,
        module_dir.to_path_buf(),
        c.ttl,
        c.queue_maxlen,
        c.rcvbuf_mb,
        c.gso,
    );
    let watcher = RouteWatcher::new().ok();
    let mut links = net::Links::default();
    let mut active4 = None::<String>;
    let mut active6 = None::<String>;
    let mut last = String::new();
    let mut failures = 0u8;
    let mut queue_progress = std::collections::BTreeMap::new();
    let mut last_drops = String::new();
    let mut warn_backlog = 0u64;
    let mut stable = Instant::now();
    let mut scan = Instant::now();
    let mut check = Instant::now();
    let mut offload_check = Instant::now();
    let mut sqm_check = Instant::now();
    let mut changed = true;
    let mut first = true;
    let mut monitor = Instant::now();
    while !STOP.load(Ordering::Relaxed) {
        if module_dir.join("disable").exists()
            || module_dir.join("remove").exists()
            || util::state_dir().join("paused").exists()
        {
            util::log("stopping: disabled/removed/paused");
            break;
        }
        if first || changed || scan.elapsed() >= Duration::from_millis(c.rescan_ms) {
            links = net::discover(&c);
            scan = Instant::now();
        }
        let sig = links.signature();
        if first || sig != last || sqm_check.elapsed() >= Duration::from_secs(30) {
            crate::qos::sync(&c, &links);
            sqm_check = Instant::now();
        }
        let check_due = first || changed || check.elapsed() >= Duration::from_millis(c.check_ms);
        let intact = if links.active() && check_due {
            check = Instant::now();
            fw.rules_ok(
                false,
                &active4,
                &links,
                backend == EffectiveBackend::Kernel,
                active_workers,
                c.ttl,
                v6,
            ) && (!(v6 == "normalize" || v6 == "block")
                || fw.rules_ok(true, &active6, &links, true, active_workers, c.ipv6_hl, v6))
        } else {
            true
        };
        if first || sig != last || !intact {
            first = false;
            if !links.active() {
                if active4.is_some() || active6.is_some() {
                    if !fw.cleanup() {
                        util::log("WARNING: cleanup failed; retrying");
                        first = true;
                    }
                    workers.stop();
                    active4 = None;
                    active6 = None;
                }
                util::write_state("phase", "idle");
                util::write_state(
                    "interfaces",
                    format!(
                        "downstream:{} upstream:{}",
                        links.down.join(" "),
                        links.up.join(" ")
                    ),
                );
            } else {
                util::write_state("phase", "installing");
                if backend == EffectiveBackend::Nfqueue
                    && !workers.healthy(active_workers)
                    && !workers.start(active_workers)
                {
                    recover(
                        &fw,
                        &mut workers,
                        &mut active4,
                        &mut active6,
                        &mut failures,
                        &mut active_workers,
                        &c,
                        "worker startup failed",
                    );
                    first = true;
                    continue;
                }
                if !fw.install4(
                    &links,
                    backend == EffectiveBackend::Kernel,
                    active_workers,
                    c.ttl,
                    &mut active4,
                ) || !fw.install6(&links, v6, c.ipv6_hl, &mut active6)
                {
                    recover(
                        &fw,
                        &mut workers,
                        &mut active4,
                        &mut active6,
                        &mut failures,
                        &mut active_workers,
                        &c,
                        "rule installation failed",
                    );
                    first = true;
                    continue;
                }
                let intf = format!(
                    "downstream:{} upstream:{}",
                    links.down.join(" "),
                    links.up.join(" ")
                );
                util::write_state("interfaces", &intf);
                util::write_state("phase", "active");
                util::log(&format!("rules active: {intf}"));
            }
            last = sig;
            queue_progress.clear();
            last_drops.clear();
            stable = Instant::now();
        }
        if backend == EffectiveBackend::Nfqueue
            && active4.is_some()
            && monitor.elapsed() >= Duration::from_millis(c.watchdog_ms as u64)
        {
            monitor = Instant::now();
            let qs = queue_stats(active_workers);
            if !workers.healthy(active_workers) || qs.rows != active_workers {
                recover(
                    &fw,
                    &mut workers,
                    &mut active4,
                    &mut active6,
                    &mut failures,
                    &mut active_workers,
                    &c,
                    "worker/queue disappeared",
                );
                first = true;
                continue;
            }
            let drops = format!("{}:{}", qs.kdrops, qs.udrops);
            let stalled = stall_sample(&mut queue_progress, &qs);
            if !last_drops.is_empty() && drops != last_drops {
                util::log(&format!(
                    "WARNING: NFQUEUE drops {last_drops} -> {drops}, backlog={}",
                    qs.len
                ));
            }
            if qs.len >= c.max_backlog {
                warn_backlog += 1;
                if warn_backlog % 20 == 1 {
                    util::log(&format!("WARNING: NFQUEUE backlog={}", qs.len));
                }
            } else {
                warn_backlog = 0;
            }
            util::write_state(
                "queue.stats",
                format!(
                    "backlog={} kernel_drops={} userspace_drops={} stalled={stalled}",
                    qs.len, qs.kdrops, qs.udrops
                ),
            );
            if stalled >= c.stall_limit {
                recover(
                    &fw,
                    &mut workers,
                    &mut active4,
                    &mut active6,
                    &mut failures,
                    &mut active_workers,
                    &c,
                    "queue stalled",
                );
                first = true;
                continue;
            }
            last_drops = drops;
        }
        if stable.elapsed() >= Duration::from_secs(60) {
            failures = 0;
        }
        if offload_check.elapsed() >= Duration::from_secs(30) {
            offload::apply(c.disable_offload);
            for w in &workers.items {
                let log = util::state_dir().join(format!("worker.{}.log", w.queue));
                if fs::metadata(&log).is_ok_and(|m| m.len() > 262144) {
                    let _ = fs::copy(&log, log.with_extension("log.1"));
                    let tail = util::tail_lines(&log, 80);
                    let _ = fs::write(&log, tail + "\n");
                }
            }
            offload_check = Instant::now();
        }
        let delay = if links.active() && backend == EffectiveBackend::Nfqueue {
            c.watchdog_ms
        } else if links.active() {
            c.check_ms.min(i32::MAX as u64) as i32
        } else {
            c.idle_ms
        };
        changed = if let Some(w) = &watcher {
            w.wait(delay)
        } else {
            thread::sleep(Duration::from_millis(delay as u64));
            false
        };
        if changed {
            thread::sleep(Duration::from_millis(100));
        }
    }
    let cleaned = fw.cleanup();
    workers.stop();
    offload::restore();
    util::remove_state("queue.stats");
    util::write_state("phase", if cleaned { "stopped" } else { "cleanup-error" });
    if cleaned {
        Ok(())
    } else {
        Err(io::Error::other("firewall cleanup incomplete"))
    }
}
#[allow(clippy::too_many_arguments)]
fn recover(
    fw: &Firewall,
    workers: &mut Workers,
    active4: &mut Option<String>,
    active6: &mut Option<String>,
    failures: &mut u8,
    active_workers: &mut u8,
    c: &Config,
    why: &str,
) {
    util::log(&format!("RECOVERY: {why}"));
    util::write_state("last-recovery", why);
    util::write_state("phase", "recovering");
    if !fw.cleanup() {
        util::log("WARNING: recovery cleanup incomplete");
    }
    *active4 = None;
    *active6 = None;
    workers.stop();
    *failures = failures.saturating_add(1);
    let mut delay = c.cooldown.saturating_mul(1u64 << (*failures).min(5));
    if *failures >= c.max_failures {
        if *active_workers > 1 {
            *active_workers = (*active_workers as u16).div_ceil(2) as u8;
            util::write_state("workers", (*active_workers).to_string());
            util::log(&format!("DEGRADE: workers={active_workers}"));
            *failures = 0;
        }
        delay = 30;
    }
    for _ in 0..delay.min(60) * 10 {
        if STOP.load(Ordering::Relaxed) || util::state_dir().join("paused").exists() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_one_stalled_queue_while_others_advance() {
        let mut previous = std::collections::BTreeMap::new();
        let mut sample = QStats {
            entries: vec![(6464, 20, 100), (6465, 5, 200)],
            ..QStats::default()
        };
        assert_eq!(stall_sample(&mut previous, &sample), 0);
        for n in 1..=3 {
            sample.entries[1].2 += 1;
            assert_eq!(stall_sample(&mut previous, &sample), n);
        }
        sample.entries[0].1 = 0;
        sample.entries[1].2 += 1;
        assert_eq!(stall_sample(&mut previous, &sample), 0);
    }
}
