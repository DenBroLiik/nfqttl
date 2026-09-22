use crate::config::{Backend,Config,Ipv6Mode};
use crate::firewall::{Firewall,QUEUE_BASE};
use crate::net::{self,RouteWatcher};
use crate::offload;
use crate::sys::*;
use crate::util;
use std::fs::{self,OpenOptions};
use std::io;
use std::path::{Path,PathBuf};
use std::process::{Child,Command,Stdio};
use std::sync::atomic::{AtomicBool,Ordering};
use std::thread;
use std::time::Duration;

static STOP:AtomicBool=AtomicBool::new(false);
extern "C" fn on_signal(_:i32){STOP.store(true,Ordering::SeqCst);}

#[derive(Clone,Copy,Debug,PartialEq,Eq)] enum EffectiveBackend{Kernel,Nfqueue}
impl EffectiveBackend{fn as_str(self)->&'static str{match self{Self::Kernel=>"kernel",Self::Nfqueue=>"nfqueue"}}}

struct Worker{queue:u16,child:Child}
struct Workers{items:Vec<Worker>,exe:PathBuf,module_dir:PathBuf,ttl:u8}
impl Workers{
    fn new(exe:PathBuf,module_dir:PathBuf,ttl:u8)->Self{Self{items:vec![],exe,module_dir,ttl}}
    fn queue_owner(q:u16)->Option<i32>{
        let s=fs::read_to_string("/proc/net/netfilter/nfnetlink_queue").ok()?;
        for line in s.lines(){let w:Vec<_>=line.split_whitespace().collect();if w.len()>=2&&w[0].parse::<u16>().ok()==Some(q){return w[1].parse().ok();}}
        None
    }
    fn stop(&mut self){
        for w in &mut self.items { let pid=w.child.id() as i32; unsafe{kill(pid,SIGTERM);} }
        thread::sleep(Duration::from_millis(500));
        for w in &mut self.items { if w.child.try_wait().ok().flatten().is_none(){let _=w.child.kill();} let _=w.child.wait(); util::remove_state(&format!("worker.{}.pid",w.queue)); }
        self.items.clear();util::remove_state("worker.pid");
    }
    fn healthy(&mut self,count:u8)->bool{
        if self.items.len()!=count as usize{return false;}
        for w in &mut self.items { if w.child.try_wait().ok().flatten().is_some(){return false;} if Self::queue_owner(w.queue)!=Some(w.child.id() as i32){return false;} }
        true
    }
    fn start(&mut self,count:u8)->bool{
        self.stop();
        for i in 0..count { let q=QUEUE_BASE+i as u16; if let Some(owner)=Self::queue_owner(q){util::log(&format!("ERROR: queue {q} already owned by pid={owner}"));return false;} }
        for i in 0..count {
            let q=QUEUE_BASE+i as u16;let log=util::state_dir().join(format!("worker.{q}.log"));let _=fs::rename(&log,util::state_dir().join(format!("worker.{q}.log.1")));
            let out=match OpenOptions::new().create(true).truncate(true).write(true).open(&log){Ok(x)=>x,Err(e)=>{util::log(&format!("ERROR: worker log: {e}"));self.stop();return false;}};let err=match out.try_clone(){Ok(x)=>x,Err(_)=>{self.stop();return false;}};
            let child=Command::new(&self.exe).arg("worker").arg("--queue").arg(q.to_string()).arg("--ttl").arg(self.ttl.to_string()).arg("--module-dir").arg(&self.module_dir).stdout(Stdio::from(out)).stderr(Stdio::from(err)).spawn();
            let Ok(child)=child else{self.stop();return false;};util::write_state(&format!("worker.{q}.pid"),child.id().to_string());if i==0{util::write_state("worker.pid",child.id().to_string());}self.items.push(Worker{queue:q,child});
        }
        for _ in 0..80 { if self.healthy(count) { let ready=self.items.iter().all(|w|util::read_trim(util::state_dir().join(format!("worker.{}.log",w.queue))).map(|x|x.contains("READY ")).unwrap_or(false));if ready{return true;} } thread::sleep(Duration::from_millis(100)); }
        false
    }
}
impl Drop for Workers{fn drop(&mut self){self.stop();}}

#[derive(Default,Clone,Debug)]struct QStats{rows:u8,len:u64,kdrops:u64,udrops:u64,progress:String}
fn queue_stats(count:u8)->QStats{
    let mut r=QStats::default();let end=QUEUE_BASE+count as u16-1;
    if let Ok(s)=fs::read_to_string("/proc/net/netfilter/nfnetlink_queue") { for line in s.lines(){let w:Vec<_>=line.split_whitespace().collect();if w.len()!=9&&w.len()<8{continue;}let Ok(q)=w[0].parse::<u16>()else{continue;};if q<QUEUE_BASE||q>end{continue;}r.rows+=1;let len=w.get(2).and_then(|x|x.parse::<u64>().ok()).unwrap_or(0);let kd=w.get(5).and_then(|x|x.parse::<u64>().ok()).unwrap_or(0);let ud=w.get(6).and_then(|x|x.parse::<u64>().ok()).unwrap_or(0);let seq=w.get(7).copied().unwrap_or("0");r.len+=len;r.kdrops+=kd;r.udrops+=ud;r.progress.push_str(&format!("{q}:{len}:{seq};")); } }
    r
}

fn boot_wait(){for _ in 0..60{if util::text("getprop", &["sys.boot_completed"]).as_deref()==Some("1"){return;}thread::sleep(Duration::from_secs(2));}}
fn acquire_lock()->io::Result<PathBuf>{
    util::ensure_state()?;let lock=util::state_dir().join("lock");
    match fs::create_dir(&lock){Ok(())=>{},Err(_) => {let pid=util::read_trim(lock.join("pid")).and_then(|x|x.parse::<i32>().ok()).unwrap_or(0);if util::owned_pid(pid,"daemon"){return Err(io::Error::new(io::ErrorKind::AlreadyExists,"daemon already running"));}let _=fs::remove_file(lock.join("pid"));let _=fs::remove_dir(&lock);fs::create_dir(&lock)?;}}
    fs::write(lock.join("pid"),std::process::id().to_string())?;Ok(lock)
}
fn release_lock(lock:&Path){let _=fs::remove_file(lock.join("pid"));let _=fs::remove_dir(lock);}

fn choose_v6(fw:&Firewall,c:&Config)->io::Result<&'static str>{
    match c.ipv6_mode {
        Ipv6Mode::Pass=>Ok("pass"),
        Ipv6Mode::Block=>if fw.ip6t.is_some(){Ok("block")}else{util::log("WARNING: ip6tables unavailable; IPv6 block cannot be enforced");Ok("pass-no-ip6tables")},
        Ipv6Mode::Normalize=>{if fw.ip6t.is_none(){Err(io::Error::new(io::ErrorKind::Other,"IPv6 normalization requested but ip6tables unavailable"))}else if fw.probe_hl(c.ipv6_hl){Ok("normalize")}else{Err(io::Error::new(io::ErrorKind::Other,"IPv6 HL target unavailable"))}},
        Ipv6Mode::Auto=>{if fw.ip6t.is_none(){util::log("WARNING: ip6tables unavailable; forwarded IPv6 cannot be normalized or blocked");Ok("pass-no-ip6tables")}else if fw.probe_hl(c.ipv6_hl){Ok("normalize")}else{Ok("block")}},
    }
}

pub fn run(module_dir:&Path)->io::Result<()> {
    STOP.store(false,Ordering::SeqCst);unsafe{signal(SIGTERM,on_signal as *const () as usize);signal(SIGINT,on_signal as *const () as usize);}
    let lock=match acquire_lock(){Ok(x)=>x,Err(e) if e.kind()==io::ErrorKind::AlreadyExists=>return Ok(()),Err(e)=>return Err(e)};
    let result=run_inner(module_dir);
    release_lock(&lock);result
}

fn run_inner(module_dir:&Path)->io::Result<()> {
    boot_wait();let fw=Firewall::select().ok_or_else(||io::Error::new(io::ErrorKind::NotFound,"usable Android iptables not found"))?;if !fw.cleanup(){return Err(io::Error::new(io::ErrorKind::Other,"initial firewall cleanup failed"));}
    let c=Config::load(&module_dir.join("config.conf"));util::log(&format!("v4.0.0-rust starting; requested={:?} ttl={} workers={} ipv6={:?}",c.backend,c.ttl,c.workers,c.ipv6_mode));
    let backend=match c.backend{Backend::Nfqueue=>EffectiveBackend::Nfqueue,Backend::Kernel=>{if fw.probe_ttl(c.ttl){EffectiveBackend::Kernel}else{return Err(io::Error::new(io::ErrorKind::Other,"kernel TTL target unavailable"));}},Backend::Auto=>if fw.probe_ttl(c.ttl){EffectiveBackend::Kernel}else{EffectiveBackend::Nfqueue}};
    let mut active_workers=if backend==EffectiveBackend::Nfqueue&&fw.probe_balance(c.workers){c.workers}else{1};let v6=choose_v6(&fw,&c)?;
    util::write_state("backend",backend.as_str());util::write_state("workers",active_workers.to_string());util::write_state("ipv6_mode",v6);offload::apply(c.disable_offload);util::log(&format!("backend={} active_workers={} ipv6_effective={v6}; restart hotspot if already active",backend.as_str(),active_workers));
    let exe=std::env::current_exe()?;let mut workers=Workers::new(exe,module_dir.to_path_buf(),c.ttl);let watcher=RouteWatcher::new().ok();
    let mut active4=None::<String>;let mut active6=None::<String>;let mut last=String::new();let mut failures=0u8;let mut stalled=0u8;let mut last_q=String::new();let mut last_drops=String::new();let mut warn_backlog=0u64;let mut stable=0u64;
    let mut fatal=None::<String>;
    while !STOP.load(Ordering::Relaxed){
        if module_dir.join("disable").exists()||module_dir.join("remove").exists()||util::state_dir().join("paused").exists(){util::log("stopping: disabled/removed/paused");break;}
        let links=net::discover(&c);let sig=links.signature();let hook4=active4.is_some()&&fw.hook4_ok();let hook6=if v6=="normalize"||v6=="block"{active6.is_some()&&fw.hook6_ok()}else{true};
        if sig!=last || (!links.down.is_empty()&&!links.up.is_empty()&&(!hook4||!hook6)) {
            if links.down.is_empty()||links.up.is_empty(){let _=fw.cleanup4();let _=fw.cleanup6();workers.stop();active4=None;active6=None;}else{
                if backend==EffectiveBackend::Nfqueue&&!workers.healthy(active_workers){workers.stop();if !workers.start(active_workers){if !recover(&fw,&mut workers,&mut active4,&mut active6,&mut failures,&mut active_workers,&c,"worker startup failed"){fatal=Some("repeated backend failures".into());break;}continue;}}
                if !fw.install4(&links,backend==EffectiveBackend::Kernel,active_workers,c.ttl,&mut active4)||!fw.install6(&links,v6,c.ipv6_hl,&mut active6){if !recover(&fw,&mut workers,&mut active4,&mut active6,&mut failures,&mut active_workers,&c,"rule installation failed"){fatal=Some("repeated backend failures".into());break;}continue;}
                let intf=format!("downstream:{} upstream:{}",links.down.join(" "),links.up.join(" "));util::write_state("interfaces",&intf);util::log(&format!("rules active: {intf}"));
            }
            last=sig;stalled=0;last_q.clear();last_drops.clear();stable=0;
        }
        if backend==EffectiveBackend::Nfqueue&&active4.is_some(){
            if !workers.healthy(active_workers){if !recover(&fw,&mut workers,&mut active4,&mut active6,&mut failures,&mut active_workers,&c,"worker/queue disappeared"){fatal=Some("repeated backend failures".into());break;}continue;}
            let qs=queue_stats(active_workers);if qs.rows!=active_workers{let expected_workers=active_workers;if !recover(&fw,&mut workers,&mut active4,&mut active6,&mut failures,&mut active_workers,&c,&format!("queue stats incomplete rows={} expected={expected_workers}",qs.rows)){fatal=Some("repeated backend failures".into());break;}continue;}
            let drops=format!("{}:{}",qs.kdrops,qs.udrops);if qs.len>0&&qs.progress==last_q{stalled=stalled.saturating_add(1);}else{stalled=0;}if !last_drops.is_empty()&&drops!=last_drops{util::log(&format!("WARNING: NFQUEUE drops changed {last_drops} -> {drops} (backlog={}); keeping service active",qs.len));}
            if qs.len>=c.max_backlog{warn_backlog+=1;if warn_backlog%5==1{util::log(&format!("WARNING: NFQUEUE backlog={} (limit={})",qs.len,c.max_backlog));}}else{warn_backlog=0;}
            if stalled>=c.stall_limit{if !recover(&fw,&mut workers,&mut active4,&mut active6,&mut failures,&mut active_workers,&c,&format!("queue stalled backlog={} drops={drops}",qs.len)){fatal=Some("repeated backend failures".into());break;}continue;}
            last_q=qs.progress;last_drops=drops;stable+=1;if stable>=60{failures=0;}
        }
        if let Some(w)=&watcher{w.wait(1000);}else{thread::sleep(Duration::from_secs(1));}
    }
    if let Some(m)=fatal{util::log(&format!("ERROR: {m}; stopping to avoid unstable firewall state"));}
    let _=fw.cleanup4();let _=fw.cleanup6();workers.stop();offload::restore();Ok(())
}

fn recover(fw:&Firewall,workers:&mut Workers,active4:&mut Option<String>,active6:&mut Option<String>,failures:&mut u8,active_workers:&mut u8,c:&Config,why:&str)->bool{
    util::log(&format!("RECOVERY: {why}"));let _=fw.cleanup4();let _=fw.cleanup6();*active4=None;*active6=None;workers.stop();*failures=failures.saturating_add(1);
    if *failures>=c.max_failures {if *active_workers>1 {*active_workers=((*active_workers as u16+1)/2) as u8;util::write_state("workers",(*active_workers).to_string());util::log(&format!("DEGRADE: reducing NFQUEUE workers to {} after repeated failures",*active_workers));*failures=0;}else{return false;}}
    thread::sleep(Duration::from_secs(c.cooldown));true
}
