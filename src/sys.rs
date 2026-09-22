use std::ffi::c_void;
use std::io;

pub const AF_INET: u8 = 2;
pub const AF_NETLINK: i32 = 16;
pub const SOCK_RAW: i32 = 3;
pub const SOCK_CLOEXEC: i32 = 0o2000000;
pub const NETLINK_ROUTE: i32 = 0;
pub const NETLINK_NETFILTER: i32 = 12;
pub const SOL_SOCKET: i32 = 1;
pub const SO_RCVBUF: i32 = 8;
pub const SO_SNDTIMEO: i32 = 21;
pub const POLLIN: i16 = 0x0001;
pub const SIGINT: i32 = 2;
pub const SIGTERM: i32 = 15;
pub const EINTR: i32 = 4;

pub const RTMGRP_LINK: u32 = 1;
pub const RTMGRP_IPV4_IFADDR: u32 = 0x10;
pub const RTMGRP_IPV4_ROUTE: u32 = 0x40;
pub const RTMGRP_IPV6_IFADDR: u32 = 0x100;
pub const RTMGRP_IPV6_ROUTE: u32 = 0x400;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SockAddrNl {
    pub nl_family: u16,
    pub nl_pad: u16,
    pub nl_pid: u32,
    pub nl_groups: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimeVal {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

extern "C" {
    pub fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    pub fn bind(fd: i32, addr: *const c_void, len: u32) -> i32;
    pub fn setsockopt(fd: i32, level: i32, optname: i32, val: *const c_void, len: u32) -> i32;
    pub fn sendto(fd: i32, buf: *const c_void, len: usize, flags: i32,
                  addr: *const c_void, addrlen: u32) -> isize;
    pub fn recv(fd: i32, buf: *mut c_void, len: usize, flags: i32) -> isize;
    pub fn recvfrom(fd: i32, buf: *mut c_void, len: usize, flags: i32,
                    addr: *mut c_void, addrlen: *mut u32) -> isize;
    pub fn poll(fds: *mut PollFd, nfds: usize, timeout: i32) -> i32;
    pub fn close(fd: i32) -> i32;
    pub fn getpid() -> i32;
    pub fn kill(pid: i32, sig: i32) -> i32;
    pub fn signal(sig: i32, handler: usize) -> usize;
}

pub fn last_error() -> io::Error { io::Error::last_os_error() }

pub struct Fd(pub i32);
impl Drop for Fd {
    fn drop(&mut self) { unsafe { close(self.0); } }
}
