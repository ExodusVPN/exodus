#![cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]
#![feature(ip)]
#![allow(unused_imports, dead_code, unused_mut, unused_must_use,unused_variables)]

#[allow(unused_imports)]
#[macro_use]
extern crate cfg_if;
#[allow(unused_imports)]
#[macro_use]
extern crate bitflags;
#[allow(unused_imports)]
#[macro_use]
extern crate logging;
extern crate netif;

extern crate byteorder;
extern crate ctrlc;
extern crate rand;
extern crate ring;
extern crate tun;
extern crate mio;
extern crate mio_more;
extern crate futures;

extern crate ipnetwork;
extern crate smoltcp;

extern crate libc;
extern crate nix;


pub mod signal;
pub mod vpn;
pub mod proxy;

use byteorder::{BigEndian, ByteOrder};

use netif::{LinkLayer, RawSocket};
use netif::interface::NetworkInterface;

use mio::Evented;
use mio::unix::EventedFd;

use smoltcp::wire;

use tun::platform::Device as TunDevice;

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::process;
use std::os::unix::io::RawFd;
use std::os::unix::io::AsRawFd;
use std::io::Write;
use std::io::Read;
use std::collections::HashMap;


const TUN_TOKEN: mio::Token = mio::Token(0);
const UDP_TOKEN: mio::Token = mio::Token(1);
const GATEWAY_TOKEN: mio::Token = mio::Token(2);

pub fn get_interface_by_name(ifname: &str) -> Option<NetworkInterface> {
    for iface in netif::interface::interfaces().iter() {
        if iface.name == ifname {
            return Some(iface.clone())
        }
    }
    None
}

pub fn find_ipv4_addr_from_interface(interface: NetworkInterface) -> Option<Ipv4Addr> {
    for addr in interface.addrs {
        match addr {
            netif::interface::Addr::Ip(ip) => match ip {
                IpAddr::V4(ipv4_addr) => return Some(ipv4_addr.clone()),
                _ => { }
            },
            _ => { }
        }
    }
    None
}

pub fn create_tun(ifname: &str, addr: Ipv4Addr, dst: Ipv4Addr, netmask: Ipv4Addr) 
        -> TunDevice {
    let mut config = tun::Configuration::default();
    config
        .address(addr)
        .netmask(netmask)
        .destination(dst)
        .mtu(1500)
        .name(ifname.clone())
        .up();
    tun::create(&config).expect("虚拟网络设备创建失败")
}

pub fn create_vpn_server(tun_ifname: &str, server_socket_addr: SocketAddr ) {
    let tun_ip = Ipv4Addr::new(172, 16, 10, 1);
    let tun_octets = tun_ip.octets();
    let tun_ip_addr = wire::Ipv4Address::from_bytes(&tun_octets);

    let tun_netmask = Ipv4Addr::new(255, 255, 255, 0);
    let mut tun_device: TunDevice = create_tun(tun_ifname, tun_ip, Ipv4Addr::new(0, 0, 0, 0), tun_netmask);

    let udp_socket_raw_fd = mio::net::UdpSocket::bind(&server_socket_addr).unwrap();
    info!("UDP Socket Listening on: {:?} ...", &server_socket_addr);
    info!("TUN ip: {:?}", tun_ip);

    let mut udp_buf = [0u8; 1600];
    let mut tun_buf = [0u8; 1600];

    let mut events = mio::Events::with_capacity(1024);
    let mut registry: HashMap<Ipv4Addr, SocketAddr> = HashMap::new();

    let poll = mio::Poll::new().unwrap();
    poll.register(&udp_socket_raw_fd, UDP_TOKEN, mio::Ready::readable(), mio::PollOpt::level()).unwrap();
    poll.register(&tun_device, TUN_TOKEN, mio::Ready::readable(), mio::PollOpt::level()).unwrap();

    info!("Ready for transmission.");
    let mut best_ip_number = u32::from(Ipv4Addr::new(172, 16, 10, 10));

    loop {
        if !signal::is_running() {
            warn!("Shutdown ...");
            break;
        }
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    let (size, remote_socket_addr) = udp_socket_raw_fd.recv_from(&mut udp_buf).unwrap();
                    if size == 0 || remote_socket_addr.ip().is_ipv6() {
                        debug!("Error Pakcet: {:?}", &udp_buf[..size]);
                        continue;
                    }
                    let cmd = udp_buf[0];
                    match cmd {
                        1 => {
                            // DHCP
                            best_ip_number += 1;
                            if let IpAddr::V4(remote_ip) = remote_socket_addr.ip() {
                                let remote_octets = remote_ip.octets();
                                let best_octets = Ipv4Addr::from(best_ip_number).octets();
                                

                                let msg = [1,
                                    best_octets[0], best_octets[1], best_octets[2], best_octets[3],
                                    remote_octets[0], remote_octets[1], remote_octets[2], remote_octets[3],
                                    tun_octets[0], tun_octets[1], tun_octets[2], tun_octets[3],
                                ];

                                udp_socket_raw_fd.send_to(&msg, &remote_socket_addr).unwrap();
                                let client_tun_ip = Ipv4Addr::from(best_ip_number);
                                debug!("为 {:?} 分配虚拟地址 {:?}", remote_socket_addr, client_tun_ip);
                                registry.insert(client_tun_ip, remote_socket_addr);
                            }
                        },
                        2 => {
                            let mut packet = &mut udp_buf[1..size];
                            if packet[0] == 69 {
                                // Ipv4
                                let mut ipv4_packet = wire::Ipv4Packet::new(&mut packet);
                                
                                let src_ip = Ipv4Addr::from(ipv4_packet.src_addr().0);
                                let dst_ip = Ipv4Addr::from(ipv4_packet.dst_addr().0);

                                ipv4_packet.set_src_addr(tun_ip_addr);
                                ipv4_packet.fill_checksum();

                                debug!("[NAT] ({:?} -> {:?}) TO ({:?} -> {:?})",
                                                        src_ip, dst_ip,
                                                        tun_ip, dst_ip);

                                // println!("[UDP] {}", &wire::PrettyPrinter::<wire::Ipv4Packet<&[u8]>>::new("", &packet));
                                // debug!("Write UDP Packet to TUN: {:?}", &packet);
                                let _ = tun_device.write(ipv4_packet.into_inner());
                            }
                        },
                        _ => { }
                    }
                },
                TUN_TOKEN => {
                    let size: usize = tun_device.read(&mut tun_buf[1..]).unwrap();
                    if size == 0 {
                        continue;
                    }
                    let data = if cfg!(target_os = "macos") {
                        tun_buf[4] = 2;
                        &tun_buf[4..size+1]
                    } else if cfg!(target_os = "linux") {
                        tun_buf[0] = 2;
                        &tun_buf[..size+1]
                    } else {
                        panic!("oops ...");
                    };

                    // debug!("Read TUN Packet: {:?}", &data);

                    let packet = &data[1..];
                    if packet[0] == 69 {
                        // Ipv4
                        let ipv4_packet = wire::Ipv4Packet::new(&packet);
                        let dst_ip = Ipv4Addr::from(ipv4_packet.dst_addr().0);
                        println!("[TUN] {}", &wire::PrettyPrinter::<wire::Ipv4Packet<&[u8]>>::new("", &packet));
                        match registry.get(&dst_ip) {
                            Some(remote_socket_addr) => {
                                debug!("Send TUN Packet to UDP: {:?}", &tun_buf[..size+1]);
                                udp_socket_raw_fd.send_to(&data, remote_socket_addr).unwrap();
                            }
                            None => { }
                        }
                    } else if packet[0] == 96 {
                        continue;
                    }
                },
                _ => { }
            }
        }
    }
}

fn dhcp_request(udp_socket: &UdpSocket, buf: &mut [u8]) -> (Ipv4Addr, Ipv4Addr, Ipv4Addr) {
    let msg = [1u8];
    let size = udp_socket.send(&msg).expect("couldn't send message");
    assert_eq!(size, 1);

    let size = udp_socket.recv(buf).expect("recv function failed");
    if size == 0 {
        error!("虚拟网络地址申请失败！");
        process::exit(1);
    }

    if buf[0] != 1 {
        warn!("Shutdown ...");
        process::exit(1);
    }

    let internal_ip = Ipv4Addr::from(BigEndian::read_u32(&buf[1..5]));
    let public_ip = Ipv4Addr::from(BigEndian::read_u32(&buf[5..9]));
    let server_gateway_ip = Ipv4Addr::from(BigEndian::read_u32(&buf[9..14]));
    (internal_ip, public_ip, server_gateway_ip)
}

pub fn create_vpn_client(tun_ifname: &str, gateway_ifname: &str, server_socket_addr: SocketAddr) {
    
    let gateway_interface = get_interface_by_name(gateway_ifname).unwrap();
    let gateway_interface_ip = find_ipv4_addr_from_interface(gateway_interface).unwrap();
    
    let udp_socket = {
        let local_udp_socket_addr = SocketAddr::new(IpAddr::V4(gateway_interface_ip), 9251);

        let s = UdpSocket::bind(&local_udp_socket_addr).expect("couldn't bind to address");
        debug!("client running on {:?}", local_udp_socket_addr);
        s.connect(&server_socket_addr).expect("connect function failed");
        debug!("connect to {:?}", server_socket_addr);
        s
    };

    let mut udp_buf = [0u8; 1600];
    let mut tun_buf = [0u8; 1600];

    let (tun_ip, public_ip, server_tun_ip) = dhcp_request(&udp_socket, &mut udp_buf);

    let tun_netmask = Ipv4Addr::new(255, 255, 255, 0);
    let mut tun_device: TunDevice = create_tun(tun_ifname, tun_ip, server_tun_ip, tun_netmask);
    info!("TUN running on {:?} -> {:?}", tun_ip, server_tun_ip);

    let udp_socket_raw_fd = mio::net::UdpSocket::from_socket(udp_socket).unwrap();

    
    let mut events = mio::Events::with_capacity(1024);
    let poll = mio::Poll::new().unwrap();

    poll.register(&udp_socket_raw_fd, UDP_TOKEN, mio::Ready::readable(), mio::PollOpt::level()).unwrap();
    poll.register(&tun_device, TUN_TOKEN, mio::Ready::readable(), mio::PollOpt::level()).unwrap();
    // let gateway_raw_socket = RawSocket::open(gateway_ifname).unwrap();
    // poll.register(&EventedFd(&gateway_raw_socket.as_raw_fd()),
    //               GATEWAY_TOKEN, mio::Ready::readable(),
    //               mio::PollOpt::level()).unwrap();

    info!("Ready for transmission.");
    loop {
        if !signal::is_running() {
            warn!("Shutdown ...");
            break;
        }
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    let size = udp_socket_raw_fd.recv(&mut udp_buf).unwrap();
                    let cmd = udp_buf[0];
                    if cmd != 2 {
                        continue;
                    }
                    let packet = &udp_buf[1..size];
                    println!("[UDP] {}", &wire::PrettyPrinter::<wire::Ipv4Packet<&[u8]>>::new("", &packet));
                    let _ = tun_device.write(packet);
                },
                TUN_TOKEN => {
                    let size: usize = tun_device.read(&mut tun_buf[1..]).unwrap();
                    if size == 0 {
                        continue;
                    }
                    let data = if cfg!(target_os = "macos") {
                        // IPv4: [0, 0, 0, 2]
                        tun_buf[4] = 2;
                        &tun_buf[4..size+1]
                    } else if cfg!(target_os = "linux") {
                        tun_buf[0] = 2;
                        &tun_buf[..size+1]
                    } else {
                        panic!("oops ...");
                    };

                    let packet = &data[1..];
                    println!("[TUN] {}", &wire::PrettyPrinter::<wire::Ipv4Packet<&[u8]>>::new("", &packet));
                    udp_socket_raw_fd.send(&data).unwrap();
                },
                _ => { }
            }
        }
    }
    drop(tun_device);
}


pub fn create_proxy_server() {

}

pub fn create_proxy_client() {

}