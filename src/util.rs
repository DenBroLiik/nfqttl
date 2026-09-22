use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

pub const STATE: &str = "/data/adb/nfqttl-state";

pub fn state_dir() -> PathBuf { std::env::var_os("NFQTTL_STATE").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(STATE)) }
pub fn ensure_state() -> io::Result<()> { fs::create_dir_all(state_dir()) }

fn timestamp() -> String {
    if let Ok(o)=Command::new("date").arg("+%F %T").output() {
        let s=String::from_utf8_lossy(&o.stdout).trim().to_string(); if !s.is_empty(){return s;}
    }
    let n=SystemTime::now().duration_since(UNIX_EPOCH).map(|x|x.as_secs()).unwrap_or(0);
    format!("unix:{n}")
}

pub fn log(msg:&str) {
    let _=ensure_state(); let path=state_dir().join("service.log");
    if fs::metadata(&path).map(|m|m.len()>262144).unwrap_or(false) { let _=fs::rename(&path,state_dir().join("service.log.1")); }
    if let Ok(mut f)=OpenOptions::new().create(true).append(true).open(path) { let _=writeln!(f,"{} {}",timestamp(),msg); }
}

pub fn output(cmd:&str,args:&[&str])->io::Result<Output>{ Command::new(cmd).args(args).output() }
pub fn ok(cmd:&str,args:&[&str])->bool{ output(cmd,args).map(|o|o.status.success()).unwrap_or(false) }
pub fn text(cmd:&str,args:&[&str])->Option<String>{ output(cmd,args).ok().filter(|o|o.status.success()).map(|o|String::from_utf8_lossy(&o.stdout).trim().to_string()) }

pub fn read_trim(path:impl AsRef<Path>)->Option<String>{ fs::read_to_string(path).ok().map(|s|s.trim().to_string()) }
pub fn write_state(name:&str,value:impl AsRef<[u8]>) { let _=ensure_state(); let _=fs::write(state_dir().join(name),value); }
pub fn remove_state(name:&str){ let _=fs::remove_file(state_dir().join(name)); }
pub fn pid_alive(pid:i32)->bool { if pid<=1{return false;} unsafe{ crate::sys::kill(pid,0)==0 } }
pub fn owned_pid(pid:i32, needle:&str)->bool {
    if !pid_alive(pid){return false;} let p=format!("/proc/{pid}/cmdline");
    fs::read(p).ok().map(|b|String::from_utf8_lossy(&b).contains(needle)).unwrap_or(false)
}
pub fn module_dir_from_exe()->io::Result<PathBuf>{ std::env::current_exe()?.parent().map(Path::to_path_buf).ok_or_else(||io::Error::new(io::ErrorKind::Other,"no executable parent")) }

pub fn tail_lines(path:&Path,n:usize)->String{
    let Ok(s)=fs::read_to_string(path) else{return String::new();};
    let v:Vec<_>=s.lines().collect(); v[v.len().saturating_sub(n)..].join("\n")
}
