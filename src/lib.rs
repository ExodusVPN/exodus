#![allow(unused_imports, unused_mut, unused_variables, dead_code)]

#[macro_use]
extern crate log;
extern crate env_logger;
#[cfg(any(target_os = "android", target_os = "linux"))]
extern crate libc;
extern crate ctrlc;
extern crate mio;
extern crate znet;
extern crate tun;
extern crate crypto;
extern crate compression;
extern crate smoltcp;

pub mod signal;
pub mod vpn;
pub mod nat;


pub use smoltcp::wire::{
    EthernetAddress, EthernetProtocol,
    IpProtocol, IpVersion,
    Ipv4Cidr, Ipv4Address,
};
