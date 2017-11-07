use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
// use std::collections::HashMap;

use byteorder::{BigEndian, ByteOrder};
use mio;
use mio::Evented;
use pnet;

use gateway::SystemGateway;
use netpacket;
use signal;
use taptun::tun;


const TUN_TOKEN: mio::Token = mio::Token(0);
const UDP_TOKEN: mio::Token = mio::Token(1);

pub fn main(server_socket_addr: SocketAddr) {

    // if unsafe { libc::getuid() } > 0 {
    //     error!("请以管理员身份运行该程序！");
    //     ::std::process::exit(1);
    // }
    // let server_socket_addr =
    // "35.194.146.161:9250".parse::<SocketAddr>().unwrap();

    let addr = "0.0.0.0:9251".parse::<SocketAddr>().unwrap();
    let udp_socket = ::std::net::UdpSocket::bind(&addr).expect("couldn't bind to address");

    info!("UDP Socket Listening at: {:?} ...", addr);

    udp_socket.connect(&server_socket_addr).expect(
        "connect function failed",
    );

    info!("UDP Socket connect to {:?} ...", server_socket_addr);

    let mut buf = [0u8; 1600];

    let internal_ip: Ipv4Addr;
    let public_ip: Ipv4Addr;
    let server_gateway_ip: Ipv4Addr;

    // DHCP
    {
        let msg = [1];
        let size = udp_socket.send(&msg).expect("couldn't send message");
        assert_eq!(size, 1);

        let size = udp_socket.recv(&mut buf).expect("recv function failed");
        if size == 0 {
            error!("虚拟网络地址申请失败！");
            ::std::process::exit(1);
        }
        match buf[0] {
            1 => {
                internal_ip = Ipv4Addr::from(BigEndian::read_u32(&buf[1..5]));
                public_ip = Ipv4Addr::from(BigEndian::read_u32(&buf[5..9]));
                server_gateway_ip = Ipv4Addr::from(BigEndian::read_u32(&buf[10..14]));
            }
            _ => ::std::process::exit(1),
        };
    }

    let mut config = tun::Configuration::default();
    config
        .address(internal_ip)
        .netmask(Ipv4Addr::new(255, 255, 255, 0))
        .destination(server_gateway_ip)
        .mtu(1500)
        .name("utun10")
        .up();

    let mut tun_device = tun::create(&config).expect("虚拟网络设备创建失败");

    info!("虚拟网络设备 utun10 初始化完成，网关: 10.200.200.1 ...");
    info!("虚拟地址: {:?} ({:?})", internal_ip, public_ip);

    let mut sys_gw = SystemGateway::new().unwrap();
    // Replace default gatewat
    sys_gw.set_default(&internal_ip).unwrap();
    debug!("{:?}", sys_gw);
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

    tun_device
        .register(
            &poll,
            TUN_TOKEN,
            mio::Ready::readable(),
            mio::PollOpt::level(),
        )
        .unwrap();



    let interface_name = "en0";
    let interfaces = pnet::datalink::interfaces();
    let interface_names_match = |iface: &pnet::datalink::NetworkInterface| iface.name == interface_name;

    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();
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
    let server_ipv4_addr = match server_socket_addr.ip() {
        IpAddr::V4(a) => a,
        _ => unreachable!(),
    };
    
    ::std::thread::spawn(move || {
        loop {
            let p = rx.next().unwrap();
            let packet = pnet::packet::ethernet::EthernetPacket::new(p).unwrap();
            {
                let mut ip_payload = packet.payload().to_vec();
                let mut _ip4p = pnet::packet::ipv4::MutableIpv4Packet::new(&mut ip_payload[..]).unwrap();
                let myip: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 103);

                if _ip4p.get_destination() == myip || _ip4p.get_destination() == internal_ip {
                    println!("\n[RX] Next: {:?}", _ip4p);
                    if _ip4p.get_source() != server_ipv4_addr {
                        // tun_device.write(&buf[1..size])
                        // let mut ip_v4_header =
                            // pnet::packet::ipv4::MutableIpv4Packet::new(&mut buf[..packet.payload().len()]).unwrap();

                        _ip4p.set_destination(internal_ip);
                        let imm_header = pnet::packet::ipv4::checksum(&_ip4p.to_immutable());
                        _ip4p.set_checksum(imm_header);
                        let _ = _ip4p.packet().to_vec();
                        println!("[REBUILD] {:?}", _ip4p);
                        tun_device.write(_ip4p.packet()).unwrap();
                    }
                }
            }


        }
    });

    use pnet::packet::Packet;
    info!("Ready for transmission.");

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
                    debug!("CMD: {}", cmd);
                    match cmd {
                        2 => {
                            match netpacket::ip::Packet::from_bytes(&buf[1..size]) {
                                Ok(ip_packet) => {
                                    match ip_packet {
                                        netpacket::ip::Packet::V4(ipv4_packet) => {
                                            if ipv4_packet.dst_ip() == u32::from(internal_ip) {
                                                match tun_device.write(&buf[1..size]) {
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
                        _ => continue,
                    };
                }
                TUN_TOKEN => {
                    let size: usize = tun_device.read(&mut buf).unwrap();
                    if size == 0 {
                        continue;
                    }
                    let ip_v4_packet = {
                        // println!("\nRaw IP Packet: {:?}", &buf[..size]);

                        let mut ip_v4_header = pnet::packet::ipv4::MutableIpv4Packet::new(&mut buf[..size]).unwrap();

                        // println!("IPv4 Header: {:?}", ip_v4_header);
                        ip_v4_header.set_source(Ipv4Addr::new(192, 168, 0, 103));
                        let imm_header = pnet::packet::ipv4::checksum(&ip_v4_header.to_immutable());
                        ip_v4_header.set_checksum(imm_header);
                        let bb = ip_v4_header.packet().to_vec();
                        println!("Ipv4 New Header: {:?}", bb);
                        bb
                    };

                    let ethernet_packet_size = size + 14;
                    // println!("ethernet_packet_size: {:?}", ethernet_packet_size);
                    let mut ethernet_buffer: Vec<u8> = vec![0u8; ethernet_packet_size]; // Vec::with_capacity(ethernet_packet_size)
                    // println!("{:?}", ethernet_buffer.len());
                    // let mut _slice = ethernet_buffer.as_mut_slice();


                    let mut ethernet_packet =
                        pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer[..]).unwrap();

                    // println!("{:?}", _ethernet_packet);

                    // let mut ethernet_packet = _ethernet_packet.unwrap();



                    ethernet_packet.set_destination(sys_gw.mac_address());
                    ethernet_packet.set_source(interface.mac_address());

                    ethernet_packet.set_ethertype(pnet::packet::ethernet::EtherType::new(0x0800)); // IPv4
                    ethernet_packet.set_payload(&ip_v4_packet[..size]);

                    let p_buf = ethernet_packet.packet();
                    // println!("{:?}", p_buf);
                    // use netpacket::ethernet::Frame;
                    // use netpacket::ip::Packet
                    // pnet::packet::ipv4::MutableIpv4Packet
                    // let frame_payload = Frame::from_bytes(p_buf).unwrap().payload();
                    // let frame_payload = ethernet_packet.payload();
                    // println!("frame_payload: {:?}", frame_payload);
                    // let aa = netpacket::ip::Packet::from_bytes(frame_payload);
                    // let aa = pnet::packet::ipv4::MutableIpv4Packet::new( &mut
                    // ethernet_packet.clone().payload()[..]);
                    // println!("{:?}", aa);

                    tx.send_to(p_buf, Some(interface.clone())).unwrap().unwrap();


                    // match netpacket::ip::Packet::from_bytes(&buf[..size]) {
                    //     Ok(ip_packet) => {
                    //         match ip_packet {
                    //             netpacket::ip::Packet::V4(ipv4_packet) => {
                    //                 let dst_ip = ipv4_packet.dst_ip();

                    //                 if IpAddr::from(Ipv4Addr::from(dst_ip)) ==
                    //                     server_socket_addr.ip()
                    //                 {
                    //                     // PASS
                    //                     debug!("PASS");
                    //                 } else if dst_ip != u32::from(internal_ip) {
                    //                     let mut data = vec![2];
                    //                     data.extend(&buf[..size]);
                    //                     udp_socket_raw_fd.send(&data).unwrap();
                    //                     debug!(
                    //                         "转发 {:?} Bytes 数据 FROM {:?} TO {:?} ...",
                    //                         data.len(),
                    //                         Ipv4Addr::from(ipv4_packet.src_ip()),
                    //                         Ipv4Addr::from(ipv4_packet.dst_ip())
                    //                     );
                    //                 }
                    //             }
                    //             netpacket::ip::Packet::V6(ipv6_packet) => {}
                    //         }
                    //     }
                    //     Err(_) => {}
                    // };
                }
                _ => unreachable!(),
            }
        }
    }
}
