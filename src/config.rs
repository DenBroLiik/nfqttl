use std::fs;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend { Auto, Kernel, Nfqueue }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6Mode { Auto, Normalize, Block, Pass }

#[derive(Clone, Debug)]
pub struct Config {
    pub ttl: u8,
    pub backend: Backend,
    pub workers: u8,
    pub downstreams: Vec<String>,
    pub upstreams: Vec<String>,
    pub disable_offload: bool,
    pub ipv6_mode: Ipv6Mode,
    pub ipv6_hl: u8,
    pub max_failures: u8,
    pub cooldown: u64,
    pub max_backlog: u64,
    pub stall_limit: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self { ttl:64, backend:Backend::Auto, workers:4, downstreams:vec![], upstreams:vec![],
            disable_offload:true, ipv6_mode:Ipv6Mode::Auto, ipv6_hl:64,
            max_failures:6, cooldown:3, max_backlog:768, stall_limit:3 }
    }
}

fn unquote(s: &str) -> &str {
    let s=s.trim();
    if s.len() >= 2 && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\''))) {
        &s[1..s.len()-1]
    } else { s }
}
fn int<T: std::str::FromStr + Copy>(s:&str, default:T) -> T { s.parse().ok().unwrap_or(default) }

impl Config {
    pub fn load(path: &Path) -> Self {
        let mut c=Self::default();
        let Ok(text)=fs::read_to_string(path) else { return c; };
        for raw in text.lines() {
            let line=raw.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let Some((k,v))=line.split_once('=') else { continue; };
            let v=unquote(v);
            match k.trim() {
                "TTL" => { let n=int(v,64u16); if (1..=255).contains(&n) { c.ttl=n as u8; } }
                "BACKEND" => c.backend=match v {"kernel"=>Backend::Kernel,"nfqueue"=>Backend::Nfqueue,_=>Backend::Auto},
                "WORKERS" => { let n=int(v,4u16); if (1..=8).contains(&n) { c.workers=n as u8; } }
                "DOWNSTREAMS" => c.downstreams=v.split_whitespace().filter(|x| valid_iface(x)).map(str::to_string).collect(),
                "UPSTREAMS" => c.upstreams=v.split_whitespace().filter(|x| valid_iface(x)).map(str::to_string).collect(),
                "DISABLE_OFFLOAD" => c.disable_offload=v=="1" || v.eq_ignore_ascii_case("true"),
                "IPV6_MODE" => c.ipv6_mode=match v {"normalize"=>Ipv6Mode::Normalize,"block"=>Ipv6Mode::Block,"pass"=>Ipv6Mode::Pass,_=>Ipv6Mode::Auto},
                "IPV6_HL" => { let n=int(v,64u16); if (1..=255).contains(&n) { c.ipv6_hl=n as u8; } }
                "MAX_FAILURES" => { let n=int(v,6u16); if (1..=20).contains(&n) { c.max_failures=n as u8; } }
                "COOLDOWN" => { let n=int(v,3u64); if (1..=60).contains(&n) { c.cooldown=n; } }
                "MAX_BACKLOG" => { let n=int(v,768u64); if (32..=8192).contains(&n) { c.max_backlog=n; } }
                "STALL_LIMIT" => { let n=int(v,3u16); if (2..=10).contains(&n) { c.stall_limit=n as u8; } }
                _ => {}
            }
        }
        c
    }
}

pub fn valid_iface(s:&str)->bool {
    !s.is_empty() && s.len()<=15 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn iface_validation(){ assert!(valid_iface("rmnet_data2")); assert!(valid_iface("wlan0")); assert!(!valid_iface("x;reboot")); }
}
