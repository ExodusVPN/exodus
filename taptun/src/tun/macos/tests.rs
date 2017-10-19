#![allow(unused_imports)]

use std::net::Ipv4Addr;
use std::str::FromStr;

use tun::Tun;
use tun::configuration;
use tun::macos::create;

#[cfg(feature = "tun-test")]
#[test]
fn test_tun_create() {
    let mut config = configuration::Configuration::default();

    let addr = Ipv4Addr::from_str("192.168.50.2").unwrap();
    let netmask = Ipv4Addr::from_str("255.255.0.0").unwrap();
    let destination = Ipv4Addr::from_str("192.168.50.1").unwrap();
    let mtu = 1480;

    config.name("utun6")
          .address(addr)
          .netmask(netmask)
          .destination(destination)
          .mtu(mtu)
          .up();

    let dev = create(&config).unwrap();

    let g_addr: Ipv4Addr = dev.address().unwrap().into();
    assert_eq!(addr, g_addr);

    let g_netmask: Ipv4Addr = dev.netmask().unwrap().into();
    assert_eq!(netmask, g_netmask);

    let g_destination: Ipv4Addr = dev.destination().unwrap().into();
    assert_eq!(destination, g_destination);

    let g_mtu = dev.mtu().unwrap();
    assert_eq!(mtu, g_mtu);
}
