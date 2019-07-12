#![allow(unused_imports, unused_mut, unused_variables, dead_code)]

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate exodus;

use exodus::{ Ipv4Cidr, Ipv4Address, EthernetAddress, };
use exodus::vpn::{ VpnClientConfig, VpnClient, InterfaceKind, };

use std::env;
use std::io::{self, Read, Write};


fn main() {
    env::set_var("RUST_LOG", "exodus=DEBUG,vpn_client=DEBUG");
    env_logger::init();
    exodus::signal::init();
    
    let vpn_client_config = VpnClientConfig {
        tun_ifname: "utun9".to_string(),
        egress_iface_addr: Ipv4Address([192, 168, 199, 200]),
        egress_iface_gateway_addr: Ipv4Address([192, 168, 199, 1]),
        vpn_server_addr: Ipv4Address([119, 28, 213, 41]),
        vpn_server_port: 9050,
    };
    let vpn_client_config = VpnClientConfig {
        tun_ifname: "utun9".to_string(),
        egress_iface_addr: Ipv4Address([192, 168, 199, 200]),
        egress_iface_gateway_addr: Ipv4Address([192, 168, 199, 1]),
        vpn_server_addr: "192.168.199.232".parse::<Ipv4Address>().unwrap(),
        vpn_server_port: 9050,
    };

    let mut vpn_client = VpnClient::new(vpn_client_config).unwrap();
    vpn_client.run_forever().unwrap();
}