use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
// use std::collections::HashMap;

use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use byteorder::{BigEndian, ByteOrder};
use mio;
use mio::Evented;
use pnet;
use pnet::packet::Packet;

use gateway::SystemGateway;
use netpacket;
use signal;
use taptun::tun;


const TUN_TOKEN: mio::Token = mio::Token(0);
const UDP_TOKEN: mio::Token = mio::Token(1);

fn get_interface_by_name(interface_name: &str) -> Option<pnet::datalink::NetworkInterface> {
    pnet::datalink::interfaces()
        .into_iter()
        .filter(|iface: &pnet::datalink::NetworkInterface| {
            iface.name == interface_name
        })
        .next()
}

fn find_ipv4_addr_from_interface(interface: &pnet::datalink::NetworkInterface) -> Option<Ipv4Addr> {
    let addrs = interface
        .ips
        .iter()
        .filter(|ipnetwork| ipnetwork.ip().is_ipv4())
        .map(|ipnetwork| match ipnetwork.ip() {
            IpAddr::V4(ipv4_addr) => ipv4_addr,
            _ => unreachable!(),
        })
        .collect::<Vec<Ipv4Addr>>();
    if addrs.len() > 0 {
        Some(addrs[0])
    } else {
        None
    }
}

fn dhcp_request(udp_socket: &::std::net::UdpSocket, buf: &mut [u8]) -> (Ipv4Addr, Ipv4Addr, Ipv4Addr) {
    let msg = [1];
    let size = udp_socket.send(&msg).expect("couldn't send message");
    assert_eq!(size, 1);

    let size = udp_socket.recv(buf).expect("recv function failed");
    if size == 0 {
        error!("虚拟网络地址申请失败！");
        ::std::process::exit(1);
    }

    if buf[0] != 1 {
        ::std::process::exit(1);
    }
    let internal_ip = Ipv4Addr::from(BigEndian::read_u32(&buf[1..5]));
    let public_ip = Ipv4Addr::from(BigEndian::read_u32(&buf[5..9]));
    let server_gateway_ip = Ipv4Addr::from(BigEndian::read_u32(&buf[10..14]));
    (internal_ip, public_ip, server_gateway_ip)
}

fn create_tun(address: Ipv4Addr, destination: Ipv4Addr) -> tun::Device {
    let mut config = tun::Configuration::default();
    config
        .address(address)
        .netmask(Ipv4Addr::new(255, 255, 255, 0))
        .destination(destination)
        .mtu(1500)
        .name("utun10")
        .up();
    tun::create(&config).expect("虚拟网络设备创建失败")
}

pub fn main(server_socket_addr: SocketAddr) {
    let server_public_ip: Ipv4Addr = match server_socket_addr.ip() {
        IpAddr::V4(a) => a,
        _ => unreachable!(),
    };
    let mut sys_gw = SystemGateway::new().unwrap();

    let interface = get_interface_by_name(sys_gw.ifname()).unwrap();
    let interface_ip = find_ipv4_addr_from_interface(&interface).expect("...");

    let local_udp_socket_addr = SocketAddr::new(IpAddr::V4(interface_ip), 9251);
    let udp_socket = ::std::net::UdpSocket::bind(&local_udp_socket_addr).expect("couldn't bind to address");
    info!("UDP Socket Listening at: {:?} ...", local_udp_socket_addr);

    udp_socket.connect(&server_socket_addr).expect(
        "connect function failed",
    );

    info!("UDP Socket connect to {:?} ...", server_socket_addr);

    let mut buf = [0u8; 1600];

    let (internal_ip, public_ip, server_gateway_ip) = dhcp_request(&udp_socket, &mut buf);
    let raw_tun_device: tun::Device = create_tun(internal_ip, server_gateway_ip);
    info!(
        "虚拟网络设备 utun10: {:?} ({:?}) --> {:?} ",
        internal_ip,
        public_ip,
        server_gateway_ip
    );

    sys_gw.set_default(&internal_ip).unwrap();
    sys_gw.add_route("-host", &server_public_ip.to_string(), &sys_gw.ipv4_addr().to_string() ).unwrap();

    warn!("系统默认路由已设置为: {}", internal_ip);


    let udp_socket_raw_fd = mio::net::UdpSocket::from_socket(udp_socket).unwrap();
    udp_socket_raw_fd.connect(server_socket_addr).unwrap();

    let mut events = mio::Events::with_capacity(1024);
    let poll = mio::Poll::new().unwrap();

    poll.register(
        &udp_socket_raw_fd,
        UDP_TOKEN,
        mio::Ready::readable(),
        mio::PollOpt::level(),
    ).unwrap();

    raw_tun_device
        .register(
            &poll,
            TUN_TOKEN,
            mio::Ready::readable(),
            mio::PollOpt::level(),
        )
        .unwrap();

    let tun_device_mutex: Arc<Mutex<tun::Device>> = Arc::new(Mutex::new(raw_tun_device));

    let (mut tx, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => {
            panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            )
        }
    };

    let tun_device_clone1 = tun_device_mutex.clone();
    ::std::thread::spawn(move || loop {
        let p = rx.next().unwrap();
        let packet = pnet::packet::ethernet::EthernetPacket::new(p).unwrap();
        {
            let mut ip_payload = packet.payload().to_vec();
            let mut _ip4p = pnet::packet::ipv4::MutableIpv4Packet::new(&mut ip_payload[..]).unwrap();

            if _ip4p.get_destination() == interface_ip || _ip4p.get_destination() == internal_ip {
                if _ip4p.get_source() != server_public_ip {
                    let origin_dst = _ip4p.get_destination();
                    _ip4p.set_destination(internal_ip);
                    let imm_header = pnet::packet::ipv4::checksum(&_ip4p.to_immutable());
                    _ip4p.set_checksum(imm_header);
                    println!("[ IN-NAT] {:?} -> {:?} TO {:?} -> {:?}  Lan: {:?} -> {:?}", 
                        _ip4p.get_source(), origin_dst, _ip4p.get_source(), _ip4p.get_destination(), 
                        packet.get_source(), packet.get_destination());
                    let mut tun_device = tun_device_clone1.lock().unwrap();
                    (*tun_device).write(_ip4p.packet()).unwrap();
                }
            }
        }
    }); 
        

    info!("Ready for transmission.");
    let tun_device_clone2 = tun_device_mutex.clone();
    loop {
        if !signal::is_running() {
            warn!("Shutdown ...");
            drop(sys_gw);
            break;
        }

        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    let size = udp_socket_raw_fd.recv(&mut buf).unwrap();
                    let cmd = buf[0];
                    if cmd != 2 {
                        continue;
                    }
                    match netpacket::ip::Packet::from_bytes(&buf[1..size]) {
                        Ok(ip_packet) => {
                            match ip_packet {
                                netpacket::ip::Packet::V4(ipv4_packet) => {
                                    if ipv4_packet.dst_ip() == u32::from(internal_ip) {
                                        let mut tun_device = tun_device_clone2.lock().unwrap();
                                        match (*tun_device).write(&buf[1..size]) {
                                            Ok(_) => {}
                                            Err(e) => {
                                                debug!("虚拟网络设备写入数据失败: {:?}", e);
                                            }
                                        };
                                    }
                                }
                                netpacket::ip::Packet::V6(_) => {}
                            }
                        }
                        Err(_) => {}
                    };
                }
                TUN_TOKEN => {
                    let mut tun_device = tun_device_clone2.lock().unwrap();
                    let size: usize = (*tun_device).read(&mut buf).unwrap();
                    if size == 0 {
                        continue;
                    }
                    let origin_src;
                    let origin_dst;
                    let ip_v4_packet = {
                        let mut ip_v4_header = pnet::packet::ipv4::MutableIpv4Packet::new(&mut buf[..size]).unwrap();
                        origin_src = ip_v4_header.get_source();
                        origin_dst = ip_v4_header.get_destination();
                        ip_v4_header.set_source(interface_ip);
                        let imm_header = pnet::packet::ipv4::checksum(&ip_v4_header.to_immutable());
                        ip_v4_header.set_checksum(imm_header);
                        ip_v4_header.packet().to_vec()
                    };

                    let ethernet_packet_size = size + 14;
                    let mut ethernet_buffer: Vec<u8> = vec![0u8; ethernet_packet_size]; // Vec::with_capacity(ethernet_packet_size)

                    let mut ethernet_packet = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer[..]).unwrap();
                    ethernet_packet.set_destination(sys_gw.mac_address());
                    ethernet_packet.set_source(interface.mac_address());

                    ethernet_packet.set_ethertype(pnet::packet::ethernet::EtherType::new(0x0800)); // IPv4
                    ethernet_packet.set_payload(&ip_v4_packet[..size]);

                    let p_buf = ethernet_packet.packet();
                    println!("[OUT-NAT] {:?} -> {:?} TO {:?} -> {:?}  Lan: {:?} -> {:?}", origin_src, origin_dst, 
                                interface_ip, origin_dst, interface.mac_address(), sys_gw.mac_address());
                    let _ = tx.send_to(p_buf, Some(interface.clone())).unwrap();
                    // println!("SendTO: {:?}\n{:?}", p_buf, s);
                }
                _ => unreachable!(),
            }
        }
    }
}
