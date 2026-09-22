use crate::config::{Config,valid_iface};
use crate::sys::*;
use crate::util;
use std::collections::BTreeSet;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;

#[derive(Clone,Debug,Default,PartialEq,Eq)]
pub struct Links { pub down:Vec<String>, pub up:Vec<String> }
impl Links { pub fn signature(&self)->String{format!("{}|{}",self.down.join(" "),self.up.join(" "))} }

fn allowed_up(s:&str)->bool { ["rmnet","ccmni","pdp","wwan","wlan","eth","tun","tap","wg","tailscale","zt"].iter().any(|p|s.starts_with(p)) }
fn allowed_down(s:&str)->bool { ["ap","ap_br","wlan","swlan","softap","wifi","rndis","usb","ncm","bnep","bt-pan","bt_pan","br"].iter().any(|p|s.starts_with(p)) }

pub fn discover(c:&Config)->Links{
    let defaults=util::text("ip", &["-4","route","show","table","all"]).unwrap_or_default().lines().filter_map(|line|{
        let w:Vec<_>=line.split_whitespace().collect(); if w.first()!=Some(&"default"){return None;} w.windows(2).find(|x|x[0]=="dev").map(|x|x[1].to_string())
    }).collect::<BTreeSet<_>>();
    let addrs=util::text("ip", &["-o","-4","addr","show"]).unwrap_or_default().lines().filter_map(|line|{
        let mut it=line.split_whitespace(); let _=it.next(); it.next().map(|s|s.split('@').next().unwrap_or(s).to_string())
    }).collect::<BTreeSet<_>>();
    let up_src:Vec<String>=if c.upstreams.is_empty(){defaults.into_iter().collect()}else{c.upstreams.clone()};
    let mut up=Vec::new();
    for x in up_src { if valid_iface(&x) && (!c.upstreams.is_empty() || allowed_up(&x)) && !up.contains(&x){up.push(x);} }
    let down_src:Vec<String>=if c.downstreams.is_empty(){addrs.into_iter().collect()}else{c.downstreams.clone()};
    let mut down=Vec::new();
    for x in down_src { if valid_iface(&x) && !up.contains(&x) && (!c.downstreams.is_empty() || allowed_down(&x)) && !down.contains(&x){down.push(x);} }
    Links{down,up}
}

pub struct RouteWatcher { fd:Fd }
impl RouteWatcher {
    pub fn new()->io::Result<Self>{
        let fd=unsafe{socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_ROUTE)}; if fd<0{return Err(last_error());}
        let fd=Fd(fd); let groups=RTMGRP_LINK|RTMGRP_IPV4_IFADDR|RTMGRP_IPV6_IFADDR|RTMGRP_IPV4_ROUTE|RTMGRP_IPV6_ROUTE;
        let addr=SockAddrNl{nl_family:AF_NETLINK as u16,nl_pad:0,nl_pid:0,nl_groups:groups};
        let r=unsafe{bind(fd.0,&addr as *const _ as *const c_void,size_of::<SockAddrNl>() as u32)}; if r<0{return Err(last_error());}
        Ok(Self{fd})
    }
    pub fn wait(&self,timeout_ms:i32){
        let mut p=PollFd{fd:self.fd.0,events:POLLIN,revents:0}; let r=unsafe{poll(&mut p,1,timeout_ms)};
        if r>0 && p.revents&POLLIN!=0 { let mut b=[0u8;8192]; unsafe{recv(self.fd.0,b.as_mut_ptr() as *mut c_void,b.len(),0);}; }
    }
}
