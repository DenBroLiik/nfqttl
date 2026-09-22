use crate::firewall::{Firewall,CHAIN6_HOOK,CHAIN_HOOK,QUEUE_BASE};
use crate::offload;
use crate::sys::*;
use crate::util;
use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command,Stdio};
use std::thread;
use std::time::Duration;

fn daemon_pid()->Option<i32>{util::read_trim(util::state_dir().join("lock/pid")).and_then(|x|x.parse().ok())}

pub fn status(module:&Path)->io::Result<()> {
    if let Ok(s)=fs::read_to_string(module.join("module.prop")){print!("{s}");}
    println!("Backend:\n{}",util::read_trim(util::state_dir().join("backend")).unwrap_or_default());
    let workers=util::read_trim(util::state_dir().join("workers")).unwrap_or_else(||"1".into());println!("NFQUEUE workers:\n{workers}");
    println!("IPv6 mode:\n{}",util::read_trim(util::state_dir().join("ipv6_mode")).unwrap_or_default());println!("Supervisor:\n{}",daemon_pid().map(|x|x.to_string()).unwrap_or_default());println!("Worker pids:");
    if let Ok(rd)=fs::read_dir(util::state_dir()){let mut v=vec![];for e in rd.flatten(){let n=e.file_name().to_string_lossy().to_string();if n.starts_with("worker.")&&n.ends_with(".pid"){v.push((n,e.path()));}}v.sort_by(|a,b|a.0.cmp(&b.0));for (n,p) in v{let q=n.trim_start_matches("worker.").trim_end_matches(".pid");println!("{q}: {}",util::read_trim(p).unwrap_or_default());}}
    println!("Paused:\n{}",if util::state_dir().join("paused").exists(){"yes"}else{"no"});if let Some(x)=util::read_trim(util::state_dir().join("interfaces")){println!("{x}");}
    if let Some(fw)=Firewall::select(){let count=workers.parse::<u16>().unwrap_or(1);println!("Queue (queue, pid, length, kernel drops, userspace drops, sequence):");if let Ok(s)=fs::read_to_string("/proc/net/netfilter/nfnetlink_queue"){for line in s.lines(){let q=line.split_whitespace().next().and_then(|x|x.parse::<u16>().ok()).unwrap_or(0);if q>=QUEUE_BASE&&q<QUEUE_BASE+count{println!("{line}");}}}println!("IPv4 hook counters:\n{}",fw.out4(&["-L",CHAIN_HOOK,"-nvx"]));if fw.ip6t.is_some(){println!("IPv6 hook counters:\n{}",fw.out6(&["-L",CHAIN6_HOOK,"-nvx"]));}}
    let tail=util::tail_lines(&util::state_dir().join("service.log"),30);if !tail.is_empty(){println!("{tail}");}Ok(())
}

pub fn stop()->io::Result<()> {
    util::ensure_state()?;fs::write(util::state_dir().join("paused"),b"")?;
    if let Some(pid)=daemon_pid(){if util::owned_pid(pid,"daemon"){unsafe{kill(pid,SIGTERM);}for _ in 0..150{if !util::pid_alive(pid){break;}thread::sleep(Duration::from_millis(100));}if util::pid_alive(pid){eprintln!("Supervisor still stopping; reboot if necessary.");}}}
    if let Some(fw)=Firewall::select(){let _=fw.cleanup();}offload::restore();println!("Stopped. Restart hotspot if you want Android offload restored immediately.");Ok(())
}

pub fn start(module:&Path)->io::Result<()> {
    if module.join("disable").exists()||module.join("remove").exists(){return Err(io::Error::new(io::ErrorKind::Other,"Enable module in Magisk/KernelSU first"));}let _=fs::remove_file(util::state_dir().join("paused"));let exe=std::env::current_exe()?;Command::new(exe).arg("daemon").arg("--module-dir").arg(module).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;println!("Start requested. Check status/service.log.");Ok(())
}
pub fn restart(module:&Path)->io::Result<()>{let _=stop();let _=fs::remove_file(util::state_dir().join("paused"));start(module)}
