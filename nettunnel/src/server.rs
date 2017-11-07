use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use mio;
use mio::Evented;

use gateway::SystemGateway;
use netpacket;
use signal;
use taptun::tun;

// sudo route add 10.200.200.1/32 -interface utun10
// sudo route add 74.125.204.94 -interface utun10
//
// curl "10.200.200.1:80"
// ping 10.200.200.1
//
// sudo route get default
// sudo route delete default
// sudo route add default -interface utun10
// netstat -nr
//
// GNU/Linux:
// ip -4 route list 0/0 | awk '{print $3}'
// macOS:
// route -n get default | grep gateway | awk '{print $2}'
//
//
// sudo iptables -t nat -A POSTROUTING -s 10.200.200.0/24 -o utun10 -j
// MASQUERADE
//
// sudo route add default -net 192.168.0.1
//
//

pub fn get_public_ip() -> Ipv4Addr {
    let output = ::std::process::Command::new("curl")
        .arg("ipecho.net/plain")
        .output()
        .expect("failed to execute `$ curl http://ipecho.net/plain` ");

    if output.status.success() == false {
        debug!("{}", String::from_utf8(output.stderr).unwrap());
        panic!("failed to execute `$ curl http://ipecho.net/plain` ");
    }

    let ip: Ipv4Addr = String::from_utf8(output.stdout).unwrap().parse().expect(
        "parse public ip fail.",
    );
    ip
}

const TUN_TOKEN: mio::Token = mio::Token(0);
const UDP_TOKEN: mio::Token = mio::Token(1);


pub fn main(socket_addr: SocketAddr, gateway_addr: Ipv4Addr) {

    let mut config = tun::Configuration::default();
    config
        .address(gateway_addr)
        .netmask(Ipv4Addr::new(255, 255, 255, 0))
        .destination(Ipv4Addr::new(0, 0, 0, 0))
        .mtu(1500)
        .name("utun10")
        .up();
    let mut tun_device = tun::create(&config).expect("虚拟网络设备创建失败");

    info!("虚拟网络设备 utun10 初始化完成，网关: 10.200.200.1 ...");

    let sys_gw = SystemGateway::new().unwrap();

    // let addr = "0.0.0.0:9250".parse::<::std::net::SocketAddr>().unwrap();
    let udp_socket_raw_fd = mio::net::UdpSocket::bind(&socket_addr).unwrap();
    info!("UDP Socket Listening on: {:?} ...", socket_addr);

    let poll = mio::Poll::new().unwrap();

    tun_device
        .register(
            &poll,
            TUN_TOKEN,
            mio::Ready::readable(),
            mio::PollOpt::level(),
        )
        .unwrap();
    poll.register(
        &udp_socket_raw_fd,
        UDP_TOKEN,
        mio::Ready::readable(),
        mio::PollOpt::level(),
    ).unwrap();


    let mut events = mio::Events::with_capacity(1024);
    let mut registry: HashMap<Ipv4Addr, SocketAddr> = HashMap::new();
    let mut buf = [0u8; 1600];

    info!("Ready for transmission.");

    let mut best_ip_number = u32::from(Ipv4Addr::new(10, 200, 200, 9));

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
                    let (size, remote_socket_addr) = udp_socket_raw_fd.recv_from(&mut buf).unwrap();
                    if size == 0 || remote_socket_addr.ip().is_ipv6() {
                        debug!("Error Pakcet: {:?}", &buf[..size]);
                        continue;
                    }
                    let cmd = buf[0];
                    match cmd {
                        1 => {
                            best_ip_number += 1;
                            if let IpAddr::V4(remote_ip) = remote_socket_addr.ip() {
                                let remote_ip_number = u32::from(remote_ip);
                                let gateway_addr_number = u32::from(gateway_addr);
                                let msg = [
                                    1,
                                    ((best_ip_number >> 24) & 0xff) as u8,
                                    ((best_ip_number >> 16) & 0xff) as u8,
                                    ((best_ip_number >> 8) & 0xff) as u8,
                                    (best_ip_number & 0xff) as u8,
                                    ((remote_ip_number >> 24) & 0xff) as u8,
                                    ((remote_ip_number >> 16) & 0xff) as u8,
                                    ((remote_ip_number >> 8) & 0xff) as u8,
                                    (remote_ip_number & 0xff) as u8,
                                    ((gateway_addr_number >> 24) & 0xff) as u8,
                                    ((gateway_addr_number >> 16) & 0xff) as u8,
                                    ((gateway_addr_number >> 8) & 0xff) as u8,
                                    (gateway_addr_number & 0xff) as u8,
                                ];
                                udp_socket_raw_fd
                                    .send_to(&msg, &remote_socket_addr)
                                    .unwrap();
                                let internal_ip = Ipv4Addr::from(best_ip_number);
                                debug!(
                                    "为 {:?} 分配虚拟地址 {:?}",
                                    remote_socket_addr,
                                    internal_ip
                                );
                                registry.insert(internal_ip, remote_socket_addr);
                            }
                        }
                        2 => {
                            let data = &buf[1..size];
                            match netpacket::ip::Packet::from_bytes(&data) {
                                Ok(ip_packet) => {
                                    match ip_packet {
                                        netpacket::ip::Packet::V4(ipv4_packet) => {
                                            let dst_ip = Ipv4Addr::from(ipv4_packet.dst_ip());
                                            if dst_ip.is_global() {
                                                // TODO: netstack -> Internet

                                            } else {
                                                match registry.get(&dst_ip) {
                                                    Some(remote_socket_addr) => {
                                                        let mut data: Vec<u8> = vec![2];
                                                        data.extend(&buf[..size]);
                                                        udp_socket_raw_fd
                                                            .send_to(&data, remote_socket_addr)
                                                            .unwrap();
                                                        debug!(
                                                            "转发 {:?} Bytes 数据 FROM {:?} TO {:?}({:?}) ...",
                                                            data.len(),
                                                            Ipv4Addr::from(ipv4_packet.src_ip()),
                                                            Ipv4Addr::from(ipv4_packet.dst_ip()),
                                                            remote_socket_addr
                                                        );
                                                    }
                                                    None => {}
                                                };
                                            }
                                            // debug!("收到 {:?} Bytes 数据 SRC: {:?}({:?}) DST: {:?}",
                                            //     data.len(),
                                            //     Ipv4Addr::from(ipv4_packet.src_ip()),
                                            //     remote_socket_addr,
                                            //     Ipv4Addr::from(ipv4_packet.dst_ip()) );
                                        }
                                        _ => {}
                                    }
                                }
                                _ => {}
                            };

                            match tun_device.write(data) {
                                Ok(_) => {}
                                Err(e) => {
                                    debug!("虚拟网络设备写入数据失败: {:?}", e);
                                }
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
                    debug!("TUN DEVICE PACKET: {:?}", &buf[..size]);

                    match netpacket::ip::Packet::from_bytes(&buf[..size]) {
                        Ok(ip_packet) => {
                            match ip_packet {
                                netpacket::ip::Packet::V4(ipv4_packet) => {
                                    let dst_ip = Ipv4Addr::from(ipv4_packet.dst_ip());
                                    match registry.get(&dst_ip) {
                                        Some(remote_socket_addr) => {
                                            let mut data: Vec<u8> = vec![2];
                                            data.extend(&buf[..size]);
                                            udp_socket_raw_fd
                                                .send_to(&data, remote_socket_addr)
                                                .unwrap();
                                            debug!(
                                                "转发 {:?} Bytes 数据 FROM {:?} TO {:?}({:?}) ...",
                                                data.len(),
                                                Ipv4Addr::from(ipv4_packet.src_ip()),
                                                Ipv4Addr::from(ipv4_packet.dst_ip()),
                                                remote_socket_addr
                                            );
                                        }
                                        None => {}
                                    };
                                }
                                netpacket::ip::Packet::V6(_) => {}
                            }
                        }
                        Err(_) => {}
                    };
                }
                _ => unreachable!(),
            }
        }
    }
    warn!("EXIT");
}
