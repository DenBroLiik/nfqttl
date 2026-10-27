use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

pub const STATE: &str = "/data/adb/nfqttl-state";
/// Single source of truth: Cargo.toml `version` plus the release flavour.
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-eclipse");

pub fn state_dir() -> PathBuf {
    std::env::var_os("NFQTTL_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(STATE))
}
pub fn ensure_state() -> io::Result<()> {
    fs::create_dir_all(state_dir())?;
    fs::set_permissions(state_dir(), fs::Permissions::from_mode(0o700))
}

fn timestamp() -> String {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|x| x.as_secs())
        .unwrap_or(0);
    format!("unix:{n}")
}

pub fn log(msg: &str) {
    let _ = ensure_state();
    let path = state_dir().join("service.log");
    if fs::metadata(&path)
        .map(|m| m.len() > 262144)
        .unwrap_or(false)
    {
        let _ = fs::rename(&path, state_dir().join("service.log.1"));
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{} {}", timestamp(), msg);
    }
}

pub fn output_path(cmd: impl AsRef<OsStr>, args: &[impl AsRef<OsStr>]) -> io::Result<Output> {
    use std::process::Stdio;
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    for fd in [out.as_raw_fd(), err.as_raw_fd()] {
        unsafe {
            let flags = crate::sys::fcntl(fd, crate::sys::F_GETFL);
            if flags < 0
                || crate::sys::fcntl(fd, crate::sys::F_SETFL, flags | crate::sys::O_NONBLOCK) < 0
            {
                let e = io::Error::last_os_error();
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        }
    }
    let drain = |r: &mut dyn Read, b: &mut Vec<u8>| {
        let mut scratch = [0u8; 8192];
        for _ in 0..128 {
            match r.read(&mut scratch) {
                Ok(0) => break,
                Ok(n) => {
                    let keep = n.min((4 * 1024 * 1024usize).saturating_sub(b.len()));
                    b.extend_from_slice(&scratch[..keep]);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(8);
    let status = loop {
        drain(&mut out, &mut stdout);
        drain(&mut err, &mut stderr);
        match child.try_wait() {
            Ok(Some(s)) => {
                drain(&mut out, &mut stdout);
                drain(&mut err, &mut stderr);
                break Ok(s);
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "command exceeded 8 seconds",
                ));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(e);
            }
        }
    };

    Ok(Output {
        status: status?,
        stdout,
        stderr,
    })
}
pub fn output(cmd: &str, args: &[&str]) -> io::Result<Output> {
    output_path(cmd, args)
}
pub fn ok(cmd: &str, args: &[&str]) -> bool {
    output(cmd, args)
        .map(|o| o.status.success())
        .unwrap_or(false)
}
pub fn text(cmd: &str, args: &[&str]) -> Option<String> {
    output(cmd, args)
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

pub fn read_trim(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}
pub fn write_state(name: &str, value: impl AsRef<[u8]>) {
    let _ = ensure_state();
    let temp = state_dir().join(format!(".{name}.{}", std::process::id()));
    if fs::write(&temp, value).is_ok() {
        let _ = fs::rename(temp, state_dir().join(name));
    }
}
pub fn remove_state(name: &str) {
    let _ = fs::remove_file(state_dir().join(name));
}
pub fn pid_alive(pid: i32) -> bool {
    if pid <= 1 {
        return false;
    }
    unsafe { crate::sys::kill(pid, 0) == 0 }
}
pub fn owned_pid(pid: i32, mode: &str) -> bool {
    if !pid_alive(pid) {
        return false;
    }
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let Ok(other) = fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    if other.to_string_lossy().trim_end_matches(" (deleted)") != exe.to_string_lossy() {
        return false;
    }
    fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|b| b.split(|x| *x == 0).nth(1) == Some(mode.as_bytes()))
        .unwrap_or(false)
}
pub fn module_dir_from_exe() -> io::Result<PathBuf> {
    std::env::current_exe()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("no executable parent"))
}

pub fn tail_lines(path: &Path, n: usize) -> String {
    let Ok(s) = fs::read_to_string(path) else {
        return String::new();
    };
    let v: Vec<_> = s.lines().collect();
    v[v.len().saturating_sub(n)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_capture_does_not_deadlock() {
        let o = output(
            "sh",
            &[
                "-c",
                "head -c 100000 /dev/zero; head -c 100000 /dev/zero >&2",
            ],
        )
        .unwrap();
        assert!(o.status.success());
        assert_eq!(o.stdout.len(), 100000);
        assert_eq!(o.stderr.len(), 100000);
    }
}
