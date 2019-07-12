#![allow(unused_imports, unused_mut, unused_variables, dead_code)]

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate exodus;

use exodus::{ Ipv4Cidr, Ipv4Address, EthernetAddress, };
use exodus::vpn::{ VpnServerConfig, VpnServer, InterfaceKind, };

use std::env;
use std::io::{self, Read, Write};


fn main() {
    env::set_var("RUST_LOG", "exodus=DEBUG,vpn_server=DEBUG");
    env_logger::init();
    exodus::signal::init();
    
    // Ubuntu Server
    let vpn_server_config = VpnServerConfig {
        tun_ifname: "utun9".to_string(),
        tun_cidr: Ipv4Cidr::new(Ipv4Address([172, 16, 0, 1]), 12),  // 172.16.0.0/12
        egress_iface_kind: InterfaceKind::Ethernet,
        egress_iface_name: "eth0".to_string(),
        egress_iface_addr: "172.19.0.7".parse::<Ipv4Address>().unwrap(),
        egress_iface_hwaddr: Some("52:54:00:8e:ae:82".parse::<EthernetAddress>().unwrap()),
        egress_iface_gateway_addr: Some("172.19.0.1".parse::<Ipv4Address>().unwrap()),
        egress_iface_gateway_hwaddr: Some("fe:ee:54:cb:79:fb".parse::<EthernetAddress>().unwrap()),
        tunnel_service_udp_port: 9050,
    };
    // Debian Server
    let vpn_server_config = VpnServerConfig {
        tun_ifname: "utun9".to_string(),
        tun_cidr: Ipv4Cidr::new(Ipv4Address([10, 192, 168, 0]), 24),  // 10.192.168.0/24
        egress_iface_kind: InterfaceKind::Ethernet,
        egress_iface_name: "enp0s3".to_string(),
        egress_iface_addr: "192.168.199.232".parse::<Ipv4Address>().unwrap(),
        egress_iface_hwaddr: Some("08:00:27:22:37:32".parse::<EthernetAddress>().unwrap()),
        egress_iface_gateway_addr: Some("192.168.199.1".parse::<Ipv4Address>().unwrap()),
        egress_iface_gateway_hwaddr: Some("d4:ee:07:5a:67:40".parse::<EthernetAddress>().unwrap()),
        tunnel_service_udp_port: 9050,
    };

    let mut vpn_server = VpnServer::new(vpn_server_config).unwrap();
    vpn_server.run_forever().unwrap();
}

