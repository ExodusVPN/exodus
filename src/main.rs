#![allow(unused_imports, unused_mut, unused_variables, dead_code)]

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


pub mod sys;
pub mod signal;
pub mod ip_forwarding;
pub mod nat;
pub mod server;
pub mod client;


use std::env;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;

use smoltcp::wire::{ EthernetAddress, IpProtocol, Ipv4Cidr, Ipv4Address, };


fn main() {
    env::set_var("RUST_LOG", "exodus=DEBUG");
    env_logger::init();

    // let vpn_server_config = server::VpnServerConfig {
    //     tun_ifname: "utun9".to_string(),
    //     tun_cidr: Ipv4Cidr::new(Ipv4Address([172, 16, 0, 1]), 16),  // 172.16.0.0/16
    //     egress_iface_kind: server::InterfaceKind::Ethernet,
    //     egress_iface_name: "en0".to_string(),
    //     egress_iface_addr: Ipv4Address([192, 168, 199, 200]),
    //     egress_iface_hwaddr: Some(EthernetAddress([0x18, 0x65, 0x90, 0xdd, 0x4c, 0x95])),
    //     egress_iface_gateway_addr: Some(Ipv4Address([192, 168, 199, 1])),
    //     egress_iface_gateway_hwaddr: Some(EthernetAddress([0xd4, 0xee, 0x07, 0x5a, 0x67, 0x40])),
    //     tunnel_service_udp_port: 9050,
    // };

    // let mut vpn_server = server::VpnServer::new(vpn_server_config).unwrap();
    // vpn_server.run_forever().unwrap();

    let vpn_client_config = client::VpnClientConfig {
        tun_ifname: "utun9".to_string(),
        egress_iface_addr: Ipv4Address([192, 168, 199, 200]),
        egress_iface_gateway_addr: Ipv4Address([192, 168, 199, 1]),
        vpn_server_addr: Ipv4Address([192, 168, 199, 201]),
        vpn_server_port: 9050,
    };
    let mut vpn_client = client::VpnClient::new(vpn_client_config).unwrap();
    vpn_client.run_forever().unwrap();
}
