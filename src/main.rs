#![deny(warnings)]
mod config;mod ctl;mod daemon;mod firewall;mod net;mod nfqueue;mod offload;mod packet;mod sys;mod util;
use std::io;
use std::path::PathBuf;

fn arg_value(args:&[String],name:&str)->Option<String>{args.windows(2).find(|x|x[0]==name).map(|x|x[1].clone())}
fn module_dir(args:&[String])->io::Result<PathBuf>{if let Some(x)=arg_value(args,"--module-dir"){Ok(PathBuf::from(x))}else{util::module_dir_from_exe()}}
fn parse_num<T:std::str::FromStr>(args:&[String],name:&str,default:T)->T{arg_value(args,name).and_then(|x|x.parse().ok()).unwrap_or(default)}
fn help(){println!("nfqttl 4.0.0-rust\nUsage:\n  nfqttl daemon [--module-dir DIR]\n  nfqttl worker --queue N --ttl N\n  nfqttl status|start|stop|restart [--module-dir DIR]\n");}
fn main(){if let Err(e)=real_main(){eprintln!("nfqttl: {e}");std::process::exit(1);}}
fn real_main()->io::Result<()> {
    let a:Vec<String>=std::env::args().collect();let cmd=a.get(1).map(String::as_str).unwrap_or("help");match cmd{
        "daemon"=>daemon::run(&module_dir(&a)?),
        "worker"=>{let q:u16=parse_num(&a,"--queue",6464);let ttl:u16=parse_num(&a,"--ttl",64);if q==0||ttl==0||ttl>255{return Err(io::Error::new(io::ErrorKind::InvalidInput,"invalid queue/ttl"));}nfqueue::worker(q,ttl as u8)},
        "status"=>ctl::status(&module_dir(&a)?),"start"=>ctl::start(&module_dir(&a)?),"stop"=>ctl::stop(),"restart"=>ctl::restart(&module_dir(&a)?),"help"|"--help"|"-h"=>{help();Ok(())},_=>{help();Err(io::Error::new(io::ErrorKind::InvalidInput,"unknown command"))}
    }
}
