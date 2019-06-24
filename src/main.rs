#[macro_use]
extern crate log;
extern crate env_logger;
#[cfg(any(target_os = "android", target_os = "linux"))]
extern crate libc;
extern crate ctrlc;
extern crate mio;
extern crate tun;
#[cfg(any(target_os = "ios", target_os = "macos", target_os = "freebsd"))]
extern crate sysctl;
extern crate smoltcp;
extern crate crypto;
extern crate compression;
extern crate znet;


pub mod signal;
pub mod sys;
pub mod ip_forwarding;


fn main() {
    println!("{:?}", ip_forwarding::ipv4_forwarding());
    println!("{:?}", ip_forwarding::enable_ipv4_forwarding());
    println!("{:?}", ip_forwarding::ipv4_forwarding());
    println!("{:?}", ip_forwarding::disable_ipv4_forwarding());
    println!("{:?}", ip_forwarding::ipv4_forwarding());
}