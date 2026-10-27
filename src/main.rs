#![deny(warnings)]
mod config;
mod ctl;
mod daemon;
mod firewall;
mod net;
mod nfqueue;
mod offload;
mod packet;
mod qos;
mod sys;
mod util;
use std::io;
use std::path::PathBuf;

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|x| x[0] == name).map(|x| x[1].clone())
}
fn module_dir(args: &[String]) -> io::Result<PathBuf> {
    if let Some(x) = arg_value(args, "--module-dir") {
        Ok(PathBuf::from(x))
    } else {
        util::module_dir_from_exe()
    }
}
fn parse_num<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> io::Result<T> {
    if !args.iter().any(|x| x == name) {
        return Ok(default);
    }
    arg_value(args, name)
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid or missing value for {name}"),
            )
        })
}
fn help() {
    println!("nfqttl 4.3.0-eclipse\nUsage:\n  nfqttl daemon [--module-dir DIR]\n  nfqttl worker --queue N --ttl N [--queue-maxlen N] [--rcvbuf-mb N]\n  nfqttl status|start|stop|restart|toggle|doctor|check|snapshot|logs|qos\n  nfqttl configure KEY=VALUE [KEY=VALUE ...] [--module-dir DIR]\n");
}
fn main() {
    if let Err(e) = real_main() {
        eprintln!("nfqttl: {e}");
        std::process::exit(1);
    }
}
fn real_main() -> io::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let cmd = a.get(1).map(String::as_str).unwrap_or("help");
    let _control = if matches!(cmd, "start" | "stop" | "restart" | "toggle" | "configure") {
        Some(ctl::control_lock()?)
    } else {
        None
    };
    match cmd {
        "daemon" => daemon::run(&module_dir(&a)?),
        "worker" => {
            let q: u16 = parse_num(&a, "--queue", 6464)?;
            let ttl: u16 = parse_num(&a, "--ttl", 64)?;
            let qmax: u32 = parse_num(&a, "--queue-maxlen", 4096)?;
            let rcv: u32 = parse_num(&a, "--rcvbuf-mb", 8)?;
            let gso: u8 = parse_num(&a, "--gso", 0)?;
            if gso > 1
                || q == 0
                || ttl == 0
                || ttl > 255
                || !(256..=32768).contains(&qmax)
                || !(1..=64).contains(&rcv)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid worker arguments",
                ));
            }
            nfqueue::worker(q, ttl as u8, qmax, rcv, gso == 1)
        }
        "configure" => {
            let end = a
                .iter()
                .position(|x| x == "--module-dir")
                .unwrap_or(a.len());
            ctl::configure(&module_dir(&a)?, &a[2..end])
        }
        "qos" => qos::status(),
        "snapshot" => ctl::snapshot(&module_dir(&a)?),
        "logs" => {
            println!(
                "{}",
                util::tail_lines(&util::state_dir().join("service.log"), 120)
            );
            Ok(())
        }
        "check" => {
            config::Config::validate(&module_dir(&a)?.join("config.conf"))?;
            println!("Configuration OK");
            Ok(())
        }
        "toggle" => ctl::toggle(&module_dir(&a)?),
        "doctor" => ctl::doctor(&module_dir(&a)?),
        "status" => ctl::status(&module_dir(&a)?),
        "start" => ctl::start(&module_dir(&a)?),
        "stop" => ctl::stop(),
        "restart" => ctl::restart(&module_dir(&a)?),
        "help" | "--help" | "-h" => {
            help();
            Ok(())
        }
        _ => {
            help();
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown command",
            ))
        }
    }
}
