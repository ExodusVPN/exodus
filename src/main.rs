#[macro_use]
extern crate log;
extern crate env_logger;
extern crate ctrlc;
extern crate mio;
extern crate tun;
extern crate smoltcp;
extern crate crypto;
extern crate compression;
extern crate sysctl;

pub mod signal;
pub mod ip_forwarding;



fn main() {
    println!("ipv4_forwarding: {:?}", ip_forwarding::ipv4_forwarding());
    println!("ipv4_forwarding: {:?}", ip_forwarding::enable_ipv4_forwarding());
}