//! Optional CAKE egress shaping. ABI pinned to Eclipse's Linux 5.4 UAPI.
use crate::{config::Config, net::Links, sys::*, util};
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::fs;
use std::io;
use std::mem::size_of;
use std::time::{Duration, Instant};

const ROOT: u32 = 0xffff_ffff;
const HANDLE: u32 = 0x7e10_0000;
const SEQ: u32 = 1;
type Options = BTreeMap<u16, Vec<u8>>;
fn bad(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn align(n: usize) -> usize {
    (n + 3) & !3
}
fn u16n(b: &[u8]) -> u16 {
    u16::from_ne_bytes(b[..2].try_into().unwrap())
}
fn u32n(b: &[u8]) -> u32 {
    u32::from_ne_bytes(b[..4].try_into().unwrap())
}
fn attr(b: &mut Vec<u8>, kind: u16, value: &[u8]) {
    b.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
    b.extend_from_slice(&kind.to_ne_bytes());
    b.extend_from_slice(value);
    b.resize(align(b.len()), 0);
}
fn attrs(mut b: &[u8]) -> io::Result<Options> {
    let mut out = BTreeMap::new();
    while !b.is_empty() {
        if b.len() < 4 {
            return Err(bad("short netlink attribute"));
        }
        let n = u16n(b) as usize;
        let k = u16n(&b[2..]) & 0x3fff;
        if n < 4 || align(n) > b.len() {
            return Err(bad("invalid netlink attribute length"));
        }
        if out.insert(k, b[4..n].to_vec()).is_some() {
            return Err(bad("duplicate netlink attribute"));
        }
        b = &b[align(n)..];
    }
    Ok(out)
}
fn encode(o: &Options) -> Vec<u8> {
    let mut b = Vec::new();
    for (k, v) in o {
        attr(&mut b, *k, v);
    }
    b
}
fn options(kbit: u32, flow: u32) -> Options {
    // BASE_RATE64 is bytes/second, not bits/second. No guessed radio overhead.
    let mut o = Options::new();
    o.insert(2, (u64::from(kbit) * 125).to_ne_bytes().to_vec());
    for (k, v) in [
        (3, 3u32),
        (4, 0),
        (5, flow),
        (6, 0),
        (7, 100_000),
        (8, 5_000),
        (9, 0),
        (10, 4 << 20),
        (11, 1),
        (12, 0),
        (13, 0),
        (14, 0),
        (15, 0),
        (16, 0),
        (17, 1),
        (18, 0),
    ] {
        o.insert(k, v.to_ne_bytes().to_vec());
    }
    o
}
#[derive(Clone, Debug)]
struct Qdisc {
    index: u32,
    parent: u32,
    handle: u32,
    kind: String,
    options: Options,
}
fn decode_qdisc(b: &[u8]) -> io::Result<Option<Qdisc>> {
    if b.len() < 20 {
        return Err(bad("short tcmsg"));
    }
    let a = attrs(&b[20..])?;
    let kind = a.get(&1).ok_or_else(|| bad("qdisc kind missing"))?;
    let kind = std::str::from_utf8(kind.strip_suffix(&[0]).unwrap_or(kind))
        .map_err(|_| bad("invalid qdisc kind"))?
        .to_owned();
    let mut o = if kind == "cake" {
        attrs(a.get(&2).ok_or_else(|| bad("CAKE options missing"))?)?
    } else {
        Options::new()
    };
    o.remove(&1); // TCA_CAKE_PAD may be inserted at any alignment.
    Ok(Some(Qdisc {
        index: u32n(&b[4..]),
        parent: u32n(&b[12..]),
        handle: u32n(&b[8..]),
        kind,
        options: o,
    }))
}
fn message(ty: u16, flags: u16, index: u32, handle: u32, o: Option<&Options>) -> Vec<u8> {
    let mut b = vec![0; 36];
    b[4..6].copy_from_slice(&ty.to_ne_bytes());
    b[6..8].copy_from_slice(&flags.to_ne_bytes());
    b[8..12].copy_from_slice(&SEQ.to_ne_bytes());
    b[20..24].copy_from_slice(&index.to_ne_bytes());
    b[24..28].copy_from_slice(&handle.to_ne_bytes());
    if ty != 38 {
        b[28..32].copy_from_slice(&ROOT.to_ne_bytes());
    }
    if let Some(o) = o {
        attr(&mut b, 1, b"cake\0");
        attr(&mut b, 2, &encode(o));
    }
    let n = b.len() as u32;
    b[..4].copy_from_slice(&n.to_ne_bytes());
    b
}
trait Backend {
    fn roots(&mut self) -> io::Result<Vec<Qdisc>>;
    fn add(&mut self, index: u32, o: &Options) -> io::Result<()>;
    fn delete(&mut self, index: u32) -> io::Result<()>;
}
struct Native;
fn request(b: &[u8], dump: bool) -> io::Result<Vec<Qdisc>> {
    let raw = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) };
    if raw < 0 {
        return Err(last_error());
    }
    let fd = Fd(raw);
    let local = SockAddrNl {
        nl_family: AF_NETLINK as u16,
        ..Default::default()
    };
    if unsafe {
        bind(
            fd.0,
            &local as *const _ as *const c_void,
            size_of::<SockAddrNl>() as u32,
        )
    } < 0
    {
        return Err(last_error());
    }
    let timeout = TimeVal {
        tv_sec: 3,
        tv_usec: 0,
    };
    if unsafe {
        setsockopt(
            fd.0,
            SOL_SOCKET,
            SO_SNDTIMEO,
            &timeout as *const _ as *const c_void,
            size_of::<TimeVal>() as u32,
        )
    } < 0
    {
        return Err(last_error());
    }
    if unsafe {
        sendto(
            fd.0,
            b.as_ptr() as *const c_void,
            b.len(),
            0,
            &local as *const _ as *const c_void,
            size_of::<SockAddrNl>() as u32,
        )
    } != b.len() as isize
    {
        return Err(last_error());
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut out = vec![];
    let mut total = 0usize;
    loop {
        let left = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(3000) as i32;
        if left == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "qdisc netlink timeout",
            ));
        }
        let mut p = PollFd {
            fd: fd.0,
            events: POLLIN,
            revents: 0,
        };
        let r = unsafe { poll(&mut p, 1, left) };
        if r < 0 {
            if last_error().raw_os_error() == Some(EINTR) {
                continue;
            }
            return Err(last_error());
        }
        if r == 0 {
            continue;
        }
        let mut buf = vec![0u8; 65536];
        let mut peer = SockAddrNl::default();
        let mut plen = size_of::<SockAddrNl>() as u32;
        let n = unsafe {
            recvfrom(
                fd.0,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                MSG_TRUNC,
                &mut peer as *mut _ as *mut c_void,
                &mut plen,
            )
        };
        if n < 0 {
            if last_error().raw_os_error() == Some(EINTR) {
                continue;
            }
            return Err(last_error());
        }
        if n == 0
            || n as usize > buf.len()
            || peer.nl_pid != 0
            || peer.nl_family != AF_NETLINK as u16
        {
            return Err(bad("invalid/truncated netlink datagram"));
        }
        total += n as usize;
        if total > 2 * 1024 * 1024 {
            return Err(bad("oversized qdisc dump"));
        }
        let mut b = &buf[..n as usize];
        while !b.is_empty() {
            if b.len() < 16 {
                return Err(bad("short netlink header"));
            }
            let len = u32n(b) as usize;
            if len < 16 || align(len) > b.len() {
                return Err(bad("invalid netlink message length"));
            }
            if u32n(&b[8..]) != SEQ {
                return Err(bad("unexpected netlink sequence"));
            }
            let ty = u16n(&b[4..]);
            let flags = u16n(&b[6..]);
            let payload = &b[16..len];
            if flags & 0x10 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "qdisc dump interrupted",
                ));
            }
            if ty == 2 || ty == 3 {
                if payload.len() < 4 {
                    return Err(bad("netlink result missing errno"));
                }
                let e = i32::from_ne_bytes(payload[..4].try_into().unwrap());
                if e < 0 {
                    return Err(io::Error::from_raw_os_error(-e));
                }
                if e > 0 {
                    return Err(bad("invalid netlink errno"));
                }
                if ty == 3 || !dump {
                    return Ok(out);
                }
            } else if ty == 36 {
                if let Some(q) = decode_qdisc(payload)? {
                    out.push(q);
                }
            } else if ty == 4 {
                return Err(bad("netlink overrun"));
            }
            b = &b[align(len)..];
        }
    }
}
impl Backend for Native {
    fn roots(&mut self) -> io::Result<Vec<Qdisc>> {
        request(&message(38, 1 | 0x300, 0, 0, None), true)
    }
    fn add(&mut self, index: u32, o: &Options) -> io::Result<()> {
        // CREATE|EXCL: cannot replace a custom root installed after our dump.
        request(
            &message(36, 1 | 4 | 0x400 | 0x200, index, HANDLE, Some(o)),
            false,
        )
        .map(|_| ())
    }
    fn delete(&mut self, index: u32) -> io::Result<()> {
        request(&message(37, 1 | 4, index, HANDLE, None), false).map(|_| ())
    }
}
fn owned(q: &Qdisc, index: u32, o: &Options) -> bool {
    q.index == index
        && q.parent == ROOT
        && q.handle == HANDLE
        && q.kind == "cake"
        && &q.options == o
}
fn replaceable(q: &Qdisc) -> bool {
    q.handle == 0
        && matches!(
            q.kind.as_str(),
            "noqueue" | "pfifo_fast" | "fq" | "fq_codel" | "mq"
        )
}
fn journal_path(iface: &str) -> std::path::PathBuf {
    util::state_dir().join(format!("sqm.{iface}.owned"))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> io::Result<Vec<u8>> {
    if s.len() > 2048 || s.len() % 2 != 0 || !s.is_ascii() {
        return Err(bad("invalid SQM journal"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| bad("invalid SQM journal")))
        .collect()
}
fn write_journal(iface: &str, index: u32, o: &Options) -> io::Result<()> {
    util::ensure_state()?;
    let dest = journal_path(iface);
    let temp = dest.with_extension("tmp");
    fs::write(&temp, format!("{index}\n{}\n", hex(&encode(o))))?;
    fs::rename(temp, dest)
}
fn journals() -> io::Result<BTreeMap<String, (u32, Options)>> {
    let mut out = BTreeMap::new();
    if !util::state_dir().exists() {
        return Ok(out);
    }
    for e in fs::read_dir(util::state_dir())? {
        let e = e?;
        let n = e.file_name();
        let n = n.to_string_lossy();
        if let Some(iface) = n
            .strip_prefix("sqm.")
            .and_then(|s| s.strip_suffix(".owned"))
        {
            if !crate::config::valid_iface(iface) {
                return Err(bad("invalid SQM journal interface"));
            }
            let s = fs::read_to_string(e.path())?;
            let mut l = s.lines();
            let idx = l
                .next()
                .and_then(|x| x.parse().ok())
                .ok_or_else(|| bad("invalid SQM journal index"))?;
            let o = attrs(&unhex(l.next().ok_or_else(|| bad("short SQM journal"))?)?)?;
            out.insert(iface.to_owned(), (idx, o));
        }
    }
    Ok(out)
}
fn reconcile(
    b: &mut impl Backend,
    wanted: &BTreeMap<String, (u32, Options)>,
) -> io::Result<String> {
    let saved = journals()?;
    if saved.is_empty() && wanted.is_empty() {
        return Ok("disabled".into());
    }
    let mut roots = b.roots()?;
    for (iface, (idx, o)) in &saved {
        if wanted.get(iface) == Some(&(*idx, o.clone())) && roots.iter().any(|q| owned(q, *idx, o))
        {
            continue;
        }
        if roots.iter().any(|q| owned(q, *idx, o)) {
            b.delete(*idx)?;
        }
        fs::remove_file(journal_path(iface))?;
    }
    // Deletion recreates the device's kernel default qdisc; re-dump before add.
    if !saved.is_empty() {
        roots = b.roots()?;
    }
    let mut active = vec![];
    for (iface, (idx, o)) in wanted {
        let q = roots.iter().find(|q| q.index == *idx && q.parent == ROOT);
        if saved.get(iface) == Some(&(*idx, o.clone())) && q.is_some_and(|q| owned(q, *idx, o)) {
            active.push(iface.clone());
            continue;
        }
        // Built-in/noop roots may be omitted by the kernel dump. EXCL still
        // rejects a conflicting visible root installed after this inspection.
        if q.is_some_and(|q| !replaceable(q))
            || roots.iter().any(|q| {
                q.index == *idx
                    && q.parent != ROOT
                    && !matches!(q.kind.as_str(), "ingress" | "clsact")
                    && q.handle != 0
            })
        {
            return Err(bad(&format!("{iface}: custom qdisc preserved")));
        }
        write_journal(iface, *idx, o)?; // Own before write: recovery covers an interrupted install.
        b.add(*idx, o)?;
        let check = b.roots()?;
        if !check.iter().any(|q| owned(q, *idx, o)) {
            return Err(bad("CAKE verification failed"));
        }
        active.push(iface.clone());
    }
    Ok(if active.is_empty() {
        "disabled".into()
    } else {
        format!("CAKE: {}", active.join(", "))
    })
}
fn desired(c: &Config, l: &Links) -> BTreeMap<String, (u32, Options)> {
    let mut out = BTreeMap::new();
    if !l.active() {
        return out;
    }
    for (iface, kbit, flow, links) in [
        (&c.sqm_up_iface, c.sqm_up_kbit, 5, &l.up),
        (&c.sqm_down_iface, c.sqm_down_kbit, 6, &l.down),
    ] {
        if kbit == 0 || !links.contains(iface) {
            continue;
        }
        if let Ok(s) = fs::read_to_string(format!("/sys/class/net/{iface}/ifindex")) {
            if let Ok(idx) = s.trim().parse::<u32>() {
                out.insert(iface.clone(), (idx, options(kbit, flow)));
            }
        }
    }
    out
}
pub fn sync(c: &Config, l: &Links) {
    let status = match reconcile(&mut Native, &desired(c, l)) {
        Ok(s) if s == "disabled" && (c.sqm_up_kbit > 0 || c.sqm_down_kbit > 0) => {
            "waiting: configured interfaces are not active".into()
        }
        Ok(s) => s,
        Err(e) => format!("error: {e}; requires CAKE kernel and CAP_NET_ADMIN"),
    };
    if util::read_trim(util::state_dir().join("sqm.status")).as_deref() != Some(&status) {
        util::log(&format!("SQM {status}"));
        util::write_state("sqm.status", status);
    }
}
pub fn cleanup() -> io::Result<()> {
    reconcile(&mut Native, &BTreeMap::new())?;
    util::write_state("sqm.status", "disabled");
    Ok(())
}
pub fn status() -> io::Result<()> {
    println!(
        "SQM: {}",
        util::read_trim(util::state_dir().join("sqm.status")).unwrap_or_else(|| "disabled".into())
    );
    for q in Native.roots()?.into_iter().filter(|q| q.parent == ROOT) {
        println!(
            "ifindex={} handle={:x} kind={} rate_kbit={}",
            q.index,
            q.handle,
            q.kind,
            q.options
                .get(&2)
                .filter(|v| v.len() == 8)
                .map(|v| u64::from_ne_bytes(v[..8].try_into().unwrap()) / 125)
                .unwrap_or(0)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ownership_and_recovery() {
        struct Fake {
            roots: Vec<Qdisc>,
            adds: usize,
            deletes: usize,
            fail: bool,
        }
        impl Backend for Fake {
            fn roots(&mut self) -> io::Result<Vec<Qdisc>> {
                Ok(self.roots.clone())
            }
            fn add(&mut self, index: u32, o: &Options) -> io::Result<()> {
                if self.fail {
                    return Err(io::Error::from_raw_os_error(2));
                }
                self.adds += 1;
                self.roots.retain(|q| q.index != index);
                self.roots.push(Qdisc {
                    index,
                    parent: ROOT,
                    handle: HANDLE,
                    kind: "cake".into(),
                    options: o.clone(),
                });
                Ok(())
            }
            fn delete(&mut self, index: u32) -> io::Result<()> {
                self.deletes += 1;
                self.roots.retain(|q| q.index != index);
                Ok(())
            }
        }
        let dir = std::env::temp_dir().join(format!("nfqttl-sqm-{}", std::process::id()));
        std::env::set_var("NFQTTL_STATE", &dir);
        let mut b = Fake {
            roots: vec![],
            adds: 0,
            deletes: 0,
            fail: false,
        };
        let mut wanted = BTreeMap::new();
        wanted.insert("rmnet_data2".into(), (2, options(8000, 5)));
        reconcile(&mut b, &wanted).unwrap();
        reconcile(&mut b, &wanted).unwrap();
        assert_eq!(b.adds, 1);
        assert_eq!(b.deletes, 0);
        wanted.insert("rmnet_data2".into(), (2, options(9000, 5)));
        reconcile(&mut b, &wanted).unwrap();
        assert_eq!(b.adds, 2);
        assert_eq!(b.deletes, 1);
        // External changes to the same CAKE handle must survive stop.
        b.roots[0].options.insert(6, 18u32.to_ne_bytes().to_vec());
        reconcile(&mut b, &BTreeMap::new()).unwrap();
        assert_eq!(b.deletes, 1);
        assert_eq!(b.roots.len(), 1);
        assert!(reconcile(&mut b, &wanted).is_err());
        assert_eq!(b.adds, 2);
        b.roots = vec![
            Qdisc {
                index: 2,
                parent: ROOT,
                handle: 0,
                kind: "mq".into(),
                options: Options::new(),
            },
            Qdisc {
                index: 2,
                parent: 1,
                handle: 0x1234_0000,
                kind: "fq_codel".into(),
                options: Options::new(),
            },
        ];
        assert!(reconcile(&mut b, &wanted).is_err()); // Custom mq child preserved.
        assert_eq!(b.adds, 2);
        b.roots.clear();
        b.fail = true;
        assert!(reconcile(&mut b, &wanted).is_err());
        assert!(journal_path("rmnet_data2").exists());
        b.fail = false;
        reconcile(&mut b, &wanted).unwrap();
        reconcile(&mut b, &BTreeMap::new()).unwrap();
        assert!(b.roots.is_empty());
        assert!(journals().unwrap().is_empty());
        std::env::remove_var("NFQTTL_STATE");
        let _ = fs::remove_dir_all(dir);
    }
    #[test]
    fn abi_and_corruption() {
        let o = options(8000, 5);
        assert_eq!(o[&2], 1_000_000u64.to_ne_bytes());
        assert_eq!(attrs(&encode(&o)).unwrap(), o);
        assert!(attrs(&[3, 0, 1, 0]).is_err());
        assert!(attrs(&[8, 0, 1, 0, 0]).is_err());
        let b = message(36, 0x605, 2, HANDLE, Some(&o));
        let q = decode_qdisc(&b[16..]).unwrap().unwrap();
        assert!(owned(&q, 2, &o));
        assert!(!owned(&q, 3, &o));
        let mut changed = q.clone();
        changed.options.insert(6, 18u32.to_ne_bytes().to_vec());
        assert!(!owned(&changed, 2, &o));
        changed.handle = 0;
        changed.kind = "htb".into();
        assert!(!replaceable(&changed));
    }
}
