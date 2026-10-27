use crate::packet::set_ipv4_ttl;
use crate::sys::*;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLMSG_ERROR: u16 = 2;
const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;
const NFNETLINK_V0: u8 = 0;
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_COPY_PACKET: u8 = 2;
const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_PAYLOAD: u16 = 10;
const NFQA_CAP_LEN: u16 = 13;
const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;
const NFQA_CFG_F_FAIL_OPEN: u32 = 1;
const NFQA_CFG_F_GSO: u32 = 4;
const NF_INET_FORWARD: u8 = 2;
const NF_ACCEPT: u32 = 1;
const NLA_TYPE_MASK: u16 = 0x3fff;

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_signal(_: i32) {
    STOP.store(true, Ordering::SeqCst);
}
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NlHdr {
    len: u32,
    ty: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

fn push_struct<T: Copy>(v: &mut Vec<u8>, x: &T) {
    unsafe {
        let p = x as *const T as *const u8;
        v.extend_from_slice(std::slice::from_raw_parts(p, size_of::<T>()));
    }
}
fn begin_into(v: &mut Vec<u8>, ty: u16, flags: u16, seq: u32, queue: u16) {
    let h = NlHdr {
        len: (size_of::<NlHdr>() + 4) as u32,
        ty: (NFNL_SUBSYS_QUEUE << 8) | ty,
        flags: NLM_F_REQUEST | flags,
        seq,
        pid: 0,
    };
    v.clear();
    push_struct(v, &h);
    v.push(AF_INET);
    v.push(NFNETLINK_V0);
    v.extend_from_slice(&queue.to_be_bytes());
}
fn begin(ty: u16, flags: u16, seq: u32, queue: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(1024);
    begin_into(&mut v, ty, flags, seq, queue);
    v
}
fn finish_len(v: &mut [u8]) {
    let len = v.len() as u32;
    v[0..4].copy_from_slice(&len.to_ne_bytes());
}
fn attr(v: &mut Vec<u8>, ty: u16, data: &[u8]) -> io::Result<()> {
    let pos = align4(v.len());
    while v.len() < pos {
        v.push(0);
    }
    let size = 4 + data.len();
    if size > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "netlink attr too large",
        ));
    }
    v.extend_from_slice(&(size as u16).to_ne_bytes());
    v.extend_from_slice(&ty.to_ne_bytes());
    v.extend_from_slice(data);
    while v.len() < pos + align4(size) {
        v.push(0);
    }
    finish_len(v);
    Ok(())
}
fn send(fd: i32, v: &[u8]) -> io::Result<()> {
    let k = SockAddrNl {
        nl_family: AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    let n = unsafe {
        sendto(
            fd,
            v.as_ptr() as *const c_void,
            v.len(),
            0,
            &k as *const _ as *const c_void,
            size_of::<SockAddrNl>() as u32,
        )
    };
    if n == v.len() as isize {
        Ok(())
    } else {
        Err(last_error())
    }
}
fn ack(fd: i32, v: &[u8], seq: u32) -> io::Result<()> {
    send(fd, v)?;
    let mut p = PollFd {
        fd,
        events: POLLIN,
        revents: 0,
    };
    let r = unsafe { poll(&mut p, 1, 2000) };
    if r != 1 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "netlink ack timeout",
        ));
    }
    let mut b = [0u8; 8192];
    let n = unsafe { recv(fd, b.as_mut_ptr() as *mut c_void, b.len(), 0) };
    if n < 0 {
        return Err(last_error());
    }
    let mut off = 0usize;
    let n = n as usize;
    while off + size_of::<NlHdr>() <= n {
        let len = u32::from_ne_bytes(b[off..off + 4].try_into().unwrap()) as usize;
        if len < size_of::<NlHdr>() || off + len > n {
            break;
        }
        let ty = u16::from_ne_bytes(b[off + 4..off + 6].try_into().unwrap());
        let s = u32::from_ne_bytes(b[off + 8..off + 12].try_into().unwrap());
        if ty == NLMSG_ERROR && s == seq && len >= size_of::<NlHdr>() + 4 {
            let e = i32::from_ne_bytes(b[off + 16..off + 20].try_into().unwrap());
            if e == 0 {
                return Ok(());
            }
            return Err(io::Error::from_raw_os_error(-e));
        }
        off += align4(len);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid netlink ack",
    ))
}
fn configure_params(
    fd: i32,
    queue: u16,
    seq: u32,
    queue_maxlen: u32,
    flags: u32,
) -> io::Result<()> {
    let mut v = begin(NFQNL_MSG_CONFIG, NLM_F_ACK, seq, queue);
    let mut params = Vec::with_capacity(5);
    params.extend_from_slice(&65531u32.to_be_bytes());
    params.push(NFQNL_COPY_PACKET);
    attr(&mut v, NFQA_CFG_PARAMS, &params)?;
    attr(&mut v, NFQA_CFG_QUEUE_MAXLEN, &queue_maxlen.to_be_bytes())?;
    if flags != 0 {
        attr(&mut v, NFQA_CFG_FLAGS, &flags.to_be_bytes())?;
        attr(&mut v, NFQA_CFG_MASK, &flags.to_be_bytes())?;
    }
    ack(fd, &v, seq)
}
fn configure(fd: i32, queue: u16, queue_maxlen: u32, gso: bool) -> io::Result<u32> {
    let mut v = begin(NFQNL_MSG_CONFIG, NLM_F_ACK, 1, queue);
    let cmd = [NFQNL_CFG_CMD_BIND, 0, 0, AF_INET];
    attr(&mut v, NFQA_CFG_CMD, &cmd)?;
    ack(fd, &v, 1)?;
    let best = NFQA_CFG_F_FAIL_OPEN | if gso { NFQA_CFG_F_GSO } else { 0 };
    if configure_params(fd, queue, 2, queue_maxlen, best).is_ok() {
        return Ok(best);
    }
    eprintln!("WARNING queue={queue}: GSO+FAIL_OPEN config rejected; retrying FAIL_OPEN only");
    if configure_params(fd, queue, 3, queue_maxlen, NFQA_CFG_F_FAIL_OPEN).is_ok() {
        return Ok(NFQA_CFG_F_FAIL_OPEN);
    }
    eprintln!("WARNING queue={queue}: FAIL_OPEN flag rejected; using basic NFQUEUE mode");
    configure_params(fd, queue, 4, queue_maxlen, 0)?;
    Ok(0)
}

// Rewrite only a complete packet. CAP_LEN exceeding PAYLOAD means the
// original skb is larger; sending a replacement would silently truncate it.
#[derive(Default)]
struct PacketStats {
    seen: u64,
    rewritten: u64,
    truncated: u64,
    unchanged: u64,
}
fn verdict(
    msg: &mut [u8],
    queue: u16,
    ttl: u8,
    v: &mut Vec<u8>,
    stats: &mut PacketStats,
) -> io::Result<()> {
    if msg.len() < 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short nfqueue message",
        ));
    }
    if u16::from_be_bytes([msg[18], msg[19]]) != queue {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong queue"));
    }
    let mut off = 20usize;
    let mut id = None::<[u8; 4]>;
    let mut hook = 255u8;
    let mut proto = 0u16;
    let mut cap = None::<u32>;
    let mut payload = None::<(usize, usize)>;
    while off + 4 <= msg.len() {
        let len = u16::from_ne_bytes([msg[off], msg[off + 1]]) as usize;
        let ty = u16::from_ne_bytes([msg[off + 2], msg[off + 3]]) & NLA_TYPE_MASK;
        if len < 4 || off + len > msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad nfqueue attr",
            ));
        }
        let d = &msg[off + 4..off + len];
        match ty {
            NFQA_PACKET_HDR if d.len() >= 7 => {
                id = Some(d[0..4].try_into().unwrap());
                proto = u16::from_be_bytes([d[4], d[5]]);
                hook = d[6];
            }
            NFQA_PAYLOAD => payload = Some((off + 4, d.len())),
            NFQA_CAP_LEN if d.len() == 4 => cap = Some(u32::from_be_bytes(d.try_into().unwrap())),
            _ => {}
        }
        off += align4(len);
    }
    let id = id.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing packet id"))?;
    let mut changed = false;
    stats.seen += 1;
    if proto == 0x0800 && hook == NF_INET_FORWARD {
        if let Some((p, l)) = payload {
            if cap.map(|x| x as usize == l).unwrap_or(true) {
                changed = set_ipv4_ttl(&mut msg[p..p + l], ttl);
            } else {
                stats.truncated += 1;
            }
        }
    }
    begin_into(v, NFQNL_MSG_VERDICT, 0, 0, queue);
    let mut vh = [0u8; 8];
    vh[..4].copy_from_slice(&NF_ACCEPT.to_be_bytes());
    vh[4..].copy_from_slice(&id);
    attr(v, NFQA_VERDICT_HDR, &vh)?;
    if changed {
        let (p, l) = payload.unwrap();
        attr(v, NFQA_PAYLOAD, &msg[p..p + l])?;
        stats.rewritten += 1;
    } else {
        stats.unchanged += 1;
    }
    Ok(())
}

pub fn worker(queue: u16, ttl: u8, queue_maxlen: u32, rcvbuf_mb: u32, gso: bool) -> io::Result<()> {
    STOP.store(false, Ordering::SeqCst);
    unsafe {
        signal(SIGTERM, on_signal as *const () as usize);
        signal(SIGINT, on_signal as *const () as usize);
    }
    let parent = unsafe { getppid() };
    if unsafe { prctl(PR_SET_PDEATHSIG, SIGTERM as usize, 0, 0, 0) } < 0 {
        return Err(last_error());
    }
    if unsafe { getppid() } != parent {
        return Ok(());
    }
    let fd = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER) };
    if fd < 0 {
        return Err(last_error());
    }
    let fd = Fd(fd);
    let requested = (rcvbuf_mb.saturating_mul(1024 * 1024)).min(i32::MAX as u32) as i32;
    let forced = unsafe {
        setsockopt(
            fd.0,
            SOL_SOCKET,
            SO_RCVBUFFORCE,
            &requested as *const _ as *const c_void,
            size_of::<i32>() as u32,
        )
    };
    if forced < 0 {
        unsafe {
            setsockopt(
                fd.0,
                SOL_SOCKET,
                SO_RCVBUF,
                &requested as *const _ as *const c_void,
                size_of::<i32>() as u32,
            );
        }
    }
    let tv = TimeVal {
        tv_sec: 1,
        tv_usec: 0,
    };
    unsafe {
        setsockopt(
            fd.0,
            SOL_SOCKET,
            SO_SNDTIMEO,
            &tv as *const _ as *const c_void,
            size_of::<TimeVal>() as u32,
        );
    }
    let local = SockAddrNl {
        nl_family: AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: unsafe { getpid() } as u32,
        nl_groups: 0,
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
    let flags = configure(fd.0, queue, queue_maxlen, gso)?;
    eprintln!("READY queue={queue} ttl={ttl} maxlen={queue_maxlen} rcvbuf_mb={rcvbuf_mb} flags=0x{flags:x} pid={}",unsafe{getpid()});
    let rx_size = ((rcvbuf_mb as usize) * 1024 * 1024 / 4).clamp(262144, 1048576);
    let mut rx = vec![0u8; rx_size];
    let mut tx = Vec::with_capacity(65568);
    let mut stats = PacketStats::default();
    let mut report = Instant::now();
    let mut overruns = 0u64;
    while !STOP.load(Ordering::Relaxed) {
        let mut p = PollFd {
            fd: fd.0,
            events: POLLIN,
            revents: 0,
        };
        let r = unsafe { poll(&mut p, 1, 1000) };
        if r < 0 {
            let e = last_error();
            if e.raw_os_error() == Some(EINTR) {
                continue;
            }
            return Err(e);
        }
        if r == 0 {
            continue;
        }
        if p.revents & POLLIN == 0 {
            return Err(io::Error::other("nfqueue poll error"));
        }
        let mut sender = SockAddrNl::default();
        let mut sl = size_of::<SockAddrNl>() as u32;
        let n = unsafe {
            recvfrom(
                fd.0,
                rx.as_mut_ptr() as *mut c_void,
                rx.len(),
                MSG_TRUNC,
                &mut sender as *mut _ as *mut c_void,
                &mut sl,
            )
        };
        if n < 0 {
            let e = last_error();
            if e.raw_os_error() == Some(EINTR) {
                continue;
            }
            if e.raw_os_error() == Some(ENOBUFS) {
                overruns += 1;
                continue;
            }
            return Err(e);
        }
        if n as usize > rx.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated netlink datagram",
            ));
        }
        if sender.nl_pid != 0 {
            continue;
        }
        let n = n as usize;
        let mut off = 0usize;
        while off + 16 <= n {
            let len = u32::from_ne_bytes(rx[off..off + 4].try_into().unwrap()) as usize;
            if len < 16 || off + len > n {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bad netlink frame",
                ));
            }
            let ty = u16::from_ne_bytes(rx[off + 4..off + 6].try_into().unwrap());
            if ty == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET) {
                verdict(&mut rx[off..off + len], queue, ttl, &mut tx, &mut stats)?;
                send(fd.0, &tx)?;
            } else if ty == NLMSG_ERROR {
                return Err(io::Error::other("nfqueue netlink error"));
            }
            off += align4(len);
        }
        if report.elapsed() >= Duration::from_secs(30) {
            eprintln!("STATS queue={queue} seen={} rewritten={} unchanged={} truncated={} enobufs={overruns}",stats.seen,stats.rewritten,stats.unchanged,stats.truncated);
            report = Instant::now();
        }
    }
    eprintln!(
        "STOP queue={queue} seen={} rewritten={} truncated={} enobufs={overruns}",
        stats.seen, stats.rewritten, stats.truncated
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn message(cap: Option<u32>) -> Vec<u8> {
        let mut m = begin(NFQNL_MSG_PACKET, 0, 1, 6464);
        attr(&mut m, NFQA_PACKET_HDR, &[0, 0, 0, 42, 8, 0, 2]).unwrap();
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[8] = 63;
        p[9] = 17;
        attr(&mut m, NFQA_PAYLOAD, &p).unwrap();
        if let Some(c) = cap {
            attr(&mut m, NFQA_CAP_LEN, &c.to_be_bytes()).unwrap();
        }
        m
    }
    #[test]
    fn complete_packet_rewritten() {
        let mut m = message(None);
        let mut v = vec![];
        let mut s = PacketStats::default();
        verdict(&mut m, 6464, 64, &mut v, &mut s).unwrap();
        assert_eq!(s.rewritten, 1);
        assert_eq!(v.len(), 76);
        assert_eq!(v[44], 64);
        assert_eq!(&v[28..32], &42u32.to_be_bytes());
    }
    #[test]
    fn truncated_gso_accepted_without_replacement() {
        let mut m = message(Some(70000));
        let mut v = vec![];
        let mut s = PacketStats::default();
        verdict(&mut m, 6464, 64, &mut v, &mut s).unwrap();
        assert_eq!(s.truncated, 1);
        assert_eq!(s.rewritten, 0);
        assert_eq!(v.len(), 32);
    }
    #[test]
    fn malformed_attributes_no_panic() {
        for n in 0..88 {
            let mut m = message(None);
            m.truncate(n);
            let _ = verdict(&mut m, 6464, 64, &mut vec![], &mut PacketStats::default());
        }
        let mut m = message(None);
        m[20..22].copy_from_slice(&65535u16.to_ne_bytes());
        assert!(verdict(&mut m, 6464, 64, &mut vec![], &mut PacketStats::default()).is_err());
    }
    #[test]
    fn rejects_wrong_queue() {
        assert!(verdict(
            &mut message(None),
            6465,
            64,
            &mut vec![],
            &mut PacketStats::default()
        )
        .is_err());
    }
}
