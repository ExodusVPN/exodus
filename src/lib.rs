#![allow(unused_imports, unused_mut, unused_variables, dead_code)]
#![cfg_attr(feature = "nightly", feature(ip))]


#[macro_use]
extern crate log;
extern crate env_logger;
extern crate ctrlc;
extern crate mio;
extern crate tun;
extern crate crypto;
extern crate compression;
extern crate smoltcp;

pub mod signal;
pub mod vpn;


pub use smoltcp::wire::{
    EthernetAddress, EthernetProtocol,
    IpProtocol, IpVersion,
    Ipv4Cidr, Ipv4Address,
};
