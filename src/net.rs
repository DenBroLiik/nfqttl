use crate::config::{valid_iface, Config};
use crate::sys::*;
use crate::util;
use std::collections::BTreeSet;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Links {
    pub down: Vec<String>,
    pub up: Vec<String>,
}
impl Links {
    pub fn signature(&self) -> String {
        format!("{}|{}", self.down.join(" "), self.up.join(" "))
    }
    pub fn active(&self) -> bool {
        !self.down.is_empty() && !self.up.is_empty()
    }
}
fn allowed_up(s: &str) -> bool {
    [
        "rmnet",
        "v4-rmnet",
        "clat",
        "ccmni",
        "pdp",
        "wwan",
        "wlan",
        "eth",
        "tun",
        "tap",
        "wg",
        "tailscale",
        "zt",
    ]
    .iter()
    .any(|p| s.starts_with(p))
}
fn allowed_down(s: &str) -> bool {
    [
        "ap", "wlan", "swlan", "softap", "wifi", "rndis", "usb", "ncm", "bnep", "bt-pan", "bt_pan",
        "br",
    ]
    .iter()
    .any(|p| s.starts_with(p))
}
fn defaults(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line| {
            let w: Vec<_> = line.split_whitespace().collect();
            if w.first() != Some(&"default") {
                return None;
            }
            w.windows(2)
                .find(|x| x[0] == "dev")
                .map(|x| x[1].to_string())
        })
        .collect()
}
fn addresses(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line| {
            let w: Vec<_> = line.split_whitespace().collect();
            let name = w.get(1)?.trim_end_matches(':').split('@').next()?;
            // Link-local IPv6 exists on inactive Wi-Fi/PAN devices too: require a
            // usable address. IPv4 USB/AP addresses and globally scoped IPv6 qualify.
            if !w.windows(2).any(|x| x == ["scope", "global"]) {
                return None;
            }
            if w.iter().any(|x| matches!(*x, "tentative" | "dadfailed")) {
                return None;
            }
            Some(name.to_string())
        })
        .collect()
}
fn classify(
    c: &Config,
    default: BTreeSet<String>,
    addrs: BTreeSet<String>,
    live: BTreeSet<String>,
) -> Links {
    let mut up: Vec<_> = if c.upstreams.is_empty() {
        default.into_iter().filter(|s| allowed_up(s)).collect()
    } else {
        c.upstreams.clone()
    };
    up.retain(|s| valid_iface(s) && live.contains(s));
    up.sort();
    up.dedup();
    let mut down: Vec<_> = if c.downstreams.is_empty() {
        addrs.into_iter().filter(|s| allowed_down(s)).collect()
    } else {
        c.downstreams.clone()
    };
    down.retain(|s| valid_iface(s) && live.contains(s) && !up.contains(s));
    down.sort();
    down.dedup();
    Links { down, up }
}
pub fn discover(c: &Config) -> Links {
    let mut default =
        defaults(&util::text("ip", &["-4", "route", "show", "table", "all"]).unwrap_or_default());
    default.extend(defaults(
        &util::text("ip", &["-6", "route", "show", "table", "all"]).unwrap_or_default(),
    ));
    let addrs = addresses(&util::text("ip", &["-o", "addr", "show"]).unwrap_or_default());
    let live = util::text("ip", &["-o", "link", "show", "up"])
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            line.split_whitespace().nth(1).map(|s| {
                s.trim_end_matches(':')
                    .split('@')
                    .next()
                    .unwrap_or(s)
                    .to_string()
            })
        })
        .collect();
    classify(c, default, addrs, live)
}
pub struct RouteWatcher {
    fd: Fd,
}
impl RouteWatcher {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) };
        if fd < 0 {
            return Err(last_error());
        }
        let fd = Fd(fd);
        let groups = RTMGRP_LINK
            | RTMGRP_IPV4_IFADDR
            | RTMGRP_IPV6_IFADDR
            | RTMGRP_IPV4_ROUTE
            | RTMGRP_IPV6_ROUTE;
        let addr = SockAddrNl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: groups,
        };
        let r = unsafe {
            bind(
                fd.0,
                &addr as *const _ as *const c_void,
                size_of::<SockAddrNl>() as u32,
            )
        };
        if r < 0 {
            return Err(last_error());
        }
        Ok(Self { fd })
    }
    pub fn wait(&self, timeout_ms: i32) -> bool {
        let mut p = PollFd {
            fd: self.fd.0,
            events: POLLIN,
            revents: 0,
        };
        let r = unsafe { poll(&mut p, 1, timeout_ms) };
        if r > 0 && p.revents & POLLIN != 0 {
            let mut b = [0u8; 32768];
            for _ in 0..64 {
                if unsafe {
                    recv(
                        self.fd.0,
                        b.as_mut_ptr() as *mut c_void,
                        b.len(),
                        MSG_DONTWAIT,
                    )
                } <= 0
                {
                    break;
                }
            }
            return true;
        }
        false
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv6_and_clat() {
        let mut d=defaults("default via fe80::1 dev rmnet_data2 table 100\nunreachable default dev lo\ndefault dev v4-rmnet_data2");
        let a=addresses("12: wlan2 inet 192.168.43.1/24 scope global wlan2\n13: bnep0 inet6 fe80::1/64 scope link\n14: rndis0 inet6 2001:db8::1/64 scope global\n15: wlan0 inet6 2001:db8::2/64 scope global tentative");
        let live = ["wlan2", "rmnet_data2", "v4-rmnet_data2", "rndis0"]
            .iter()
            .map(|x| x.to_string())
            .collect();
        d.insert("lo".into());
        let l = classify(&Config::default(), d, a, live);
        assert_eq!(l.down, vec!["rndis0", "wlan2"]);
        assert_eq!(l.up, vec!["rmnet_data2", "v4-rmnet_data2"]);
    }
    #[test]
    fn wifi_upstream_is_not_downstream() {
        let c = Config::default();
        let l = classify(
            &c,
            defaults("default dev wlan0"),
            ["wlan0", "wlan2"].iter().map(|x| x.to_string()).collect(),
            ["wlan0", "wlan2"].iter().map(|x| x.to_string()).collect(),
        );
        assert_eq!(l.down, vec!["wlan2"]);
        assert_eq!(l.up, vec!["wlan0"]);
    }
}
