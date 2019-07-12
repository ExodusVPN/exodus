use mio;
use smoltcp::wire::{
    PrettyPrinter,
    EthernetAddress, EthernetFrame, EthernetProtocol,
    IpProtocol, IpVersion,
    Ipv4Cidr, Ipv4Address, Ipv4Packet,
    TcpPacket, UdpPacket,
};

use crate::signal;
use crate::vpn::{
    InterfaceKind,
    TAP_TOKEN, TUN_TOKEN, UDP_TOKEN,
    DHCP_REQ_PACKET_SIGNATURE, DHCP_RES_PACKET_SIGNATURE,
    TUNNEL_PACKET_SIGNATURE, BYE_PACKET_SIGNATURE,
};

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::net::{ IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket, };


#[derive(Debug, Clone)]
pub struct VpnServerConfig {
    pub tun_ifname: String,
    pub tun_cidr: Ipv4Cidr,
    pub egress_iface_kind: InterfaceKind,
    pub egress_iface_name: String,
    pub egress_iface_addr: Ipv4Address,

    // NOTE: 如果 `egress_iface_kind` 设置为了 以太网(Ethernet) 模式
    //       那么下面的三个 选项参数都必须提供！
    pub egress_iface_hwaddr: Option<EthernetAddress>,
    pub egress_iface_gateway_addr: Option<Ipv4Address>,
    pub egress_iface_gateway_hwaddr: Option<EthernetAddress>,
    pub tunnel_service_udp_port: u16,
    // pub dhcp_service_udp_port: u16,
}

pub struct VpnServer {
    config  :        VpnServerConfig,
    tun_addr:        Ipv4Address,
    tun_netmask:     Ipv4Address,
    dhcp_start_addr: u32,
    dhcp_end_addr:   u32,
    dhcp_next_addr:  u32,
    neighbor  :      HashMap<Ipv4Address, SocketAddrV4>,
    buffer:          [u8; 2048],
    tun_device:      tun::Device,
    udp_socket:      mio::net::UdpSocket,
}

impl VpnServer {
    pub fn new(config: VpnServerConfig) -> Result<Self, io::Error> {
        // 172.16.0.0/16
        let tun_cidr = config.tun_cidr.network();
        let tun_cidr_start_number = u32::from_be_bytes(tun_cidr.address().0);
        let tun_cidr_end_number   = tun_cidr_start_number + 2_u32.pow(32 - tun_cidr.prefix_len() as u32) - 1;

        let tun_addr = Ipv4Addr::from(tun_cidr_start_number + 1);
        let tun_netmask = Ipv4Addr::from(tun_cidr.netmask());

        let dhcp_start_addr = tun_cidr_start_number + 5;
        let dhcp_end_addr   = tun_cidr_end_number - 5;
        let dhcp_next_addr  = dhcp_start_addr;

        let mut tun_device = tun::Device::new(&config.tun_ifname)?;
        tun_device.set_address(tun_addr)?;
        tun_device.set_netmask(tun_netmask)?;
        tun_device.set_destination(Ipv4Addr::new(0, 0, 0, 0))?;
        tun_device.set_mtu(1500)?;
        tun_device.enabled(true)?;

        // NOTE:
        // 这里需要为系统配置 静态路由
        // 在未来，这个会通过 C 库自动实现
        // 目前临时使用 命令行程序 去配置这些数据

        warn!("为系统路由表添加静态路由:
        Linux:
            # Clear iptables rules
            sudo iptables -P INPUT ACCEPT;
            sudo iptables -P FORWARD ACCEPT;
            sudo iptables -P OUTPUT ACCEPT;
            sudo iptables -t nat -F;
            sudo iptables -t mangle -F;
            sudo iptables -F;
            sudo iptables -X;

            sudo sysctl -w net.ipv4.conf.all.forwarding=1
            sudo route add -net {} dev {}
            sudo iptables -t nat -A POSTROUTING -s {} -o enp0s3 -j MASQUERADE
            sudo iptables -A OUTPUT -o {} -j ACCEPT

        macOS:
            sudo route add -net {} -interface {}
            待补充 ...
        ",
        tun_cidr, &config.tun_ifname,
        tun_cidr, &config.tun_ifname,
        tun_cidr, &config.tun_ifname,);

        std::thread::sleep(std::time::Duration::new(1, 0));

        if config.egress_iface_kind == InterfaceKind::Internet {
            // TODO: 一些网络环境没有以太网，直接接入了 因特网。
            //       据我所知，好像 `搬瓦工` 这个 VPS 提供商的系统就是这样配置的。
            //       这个有相应环境后再做测试。
            unimplemented!()
        } else {
            if config.egress_iface_hwaddr.is_none() || config.egress_iface_gateway_hwaddr.is_none() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "缺少以太网参数！"));
            }
        }

        let sa = SocketAddrV4::new(config.egress_iface_addr.into(), config.tunnel_service_udp_port);
        let mut udp_socket = mio::net::UdpSocket::bind(&sa.into())?;

        Ok(VpnServer {
            config,
            tun_addr: tun_addr.into(),
            tun_netmask: tun_netmask.into(),
            dhcp_start_addr,
            dhcp_end_addr,
            dhcp_next_addr,
            neighbor: HashMap::new(),
            buffer: [0u8; 2048],
            tun_device,
            udp_socket,
        })
    }

    fn handle_dhcp_req(&mut self, remote_socket_addr: SocketAddrV4) -> Result<(), io::Error> {
        let mut peer_tun_addr: Option<Ipv4Address> = None;

        for addr_num in self.dhcp_start_addr .. self.dhcp_end_addr {
            let addr = Ipv4Address::from(std::net::Ipv4Addr::from(addr_num));
            if !self.neighbor.contains_key(&addr) {
                peer_tun_addr = Some(addr);
                break;
            }
        }

        let dhcp_addr = peer_tun_addr.unwrap_or(Ipv4Address::UNSPECIFIED);

        // 构建数据包
        (&mut self.buffer[0..4]).copy_from_slice(&DHCP_RES_PACKET_SIGNATURE);
        (&mut self.buffer[4..8]).copy_from_slice(&dhcp_addr.0);

        (&mut self.buffer[8..12]).copy_from_slice(&self.tun_addr.0);
        (&mut self.buffer[12..16]).copy_from_slice(&self.tun_netmask.0);

        let message = &self.buffer[0..16];
        self.udp_socket.send_to(&message, &(remote_socket_addr.into()))?;
        
        if dhcp_addr != Ipv4Address::UNSPECIFIED {
            debug!("为 {} 分配虚拟地址: {}", remote_socket_addr, dhcp_addr);
            self.neighbor.insert(dhcp_addr, remote_socket_addr);
        }

        Ok(())
    }

    fn handle_tunnel_pkt(&mut self, remote_socket_addr: SocketAddrV4, pkt_amt: usize) -> Result<(), io::Error> {
        let packet = &self.buffer[4..pkt_amt];
        let ip_version = IpVersion::of_packet(&packet);
        if ip_version != Ok(IpVersion::Ipv4) {
            trace!("暂时只支持处理 IPv4 协议！");
            return Ok(());
        }

        let ipv4_packet = Ipv4Packet::new_unchecked(&packet);
        let ipv4_protocol = ipv4_packet.protocol();
        let src_ip = ipv4_packet.src_addr();
        let dst_ip = ipv4_packet.dst_addr();

        if self.config.tun_cidr.contains_addr(&dst_ip) {
            // 子网路由，直接发送，不需要经过 TUN 设备中继
            // TODO: 以后需要增加身份认证机制
            if let Some(udp_socket_addr) = self.neighbor.get(&dst_ip) {
                let message = &self.buffer[..packet.len() + 4];
                let addr = (*udp_socket_addr).into();
                let _ = self.udp_socket.send_to(&message, &addr);
            } else {
                debug!("[TUN NETWORK] 无法路由该地址: {}", dst_ip);
            }

            return Ok(());
        }
        
        let std_src_ip: Ipv4Addr = src_ip.into();
        if !std_src_ip.is_private() && !std_src_ip.is_global() {
            debug!("[TAP NETWORK] 无法路由该地址: {}", dst_ip);
            return Ok(());
        }
        
        #[cfg(target_os = "macos")]
        let packet = &self.buffer[..pkt_amt];
        #[cfg(target_os = "macos")]
        assert_eq!(&self.buffer[..4], TUNNEL_PACKET_SIGNATURE);
        
        trace!("[UDP] IPv4 {} {} --> {} ...", ipv4_protocol, src_ip, dst_ip);
        self.tun_device.write(&packet)?;

        Ok(())
    }

    pub fn handle_tun_pkt(&mut self) -> Result<(), io::Error> {
        #[cfg(target_os = "macos")]
        let amt = self.tun_device.read(&mut self.buffer)?;

        #[cfg(target_os = "linux")]
        &mut self.buffer[..4].copy_from_slice(&TUNNEL_PACKET_SIGNATURE);
        #[cfg(target_os = "linux")]
        let amt = self.tun_device.read(&mut self.buffer[4..])?;
        
        if amt <= 4 {
            trace!("[TUN] 畸形的数据包！");
            return Ok(())
        }

        let packet_signature = [
            self.buffer[0], self.buffer[1], 
            self.buffer[2], self.buffer[3], 
        ];

        #[cfg(target_os = "macos")]
        assert_eq!(packet_signature, TUNNEL_PACKET_SIGNATURE);

        #[cfg(target_os = "linux")]
        let mut packet = &self.buffer[4..amt + 4];
        #[cfg(target_os = "macos")]
        let mut packet = &self.buffer[4..amt];

        if Ok(IpVersion::Ipv4) != IpVersion::of_packet(&packet) {
            trace!("[TUN] 暂时只支持处理 IPv4 协议！");
            return Ok(());
        }
        
        let ipv4_packet = Ipv4Packet::new_unchecked(&packet);
        let ipv4_protocol = ipv4_packet.protocol();
        let src_ip = ipv4_packet.src_addr();
        let dst_ip = ipv4_packet.dst_addr();

        if self.config.tun_cidr.contains_addr(&dst_ip) {
            if let Some(udp_socket_addr) = self.neighbor.get(&dst_ip) {
                let message = &self.buffer[..packet.len() + 4];
                let addr = (*udp_socket_addr).into();
                
                debug!("[TUN] IPv4 {} {} --> {} ...", ipv4_protocol, src_ip, dst_ip);

                let _ = self.udp_socket.send_to(&message, &addr);
            } else {
                debug!("[TUN NETWORK] 无法路由该地址: {}", dst_ip);
            }
        } else {
            debug!("[TAP NETWORK] 无法路由该地址: {}", dst_ip);
        }

        Ok(())
    }


    pub fn run_forever(&mut self) -> Result<(), io::Error> {
        let mut events = mio::Events::with_capacity(2048);
        let poll = mio::Poll::new().unwrap();

        poll.register(&self.udp_socket, UDP_TOKEN, mio::Ready::readable(), mio::PollOpt::edge())?;
        poll.register(&self.tun_device, TUN_TOKEN, mio::Ready::readable(), mio::PollOpt::edge())?;

        let timeout = std::time::Duration::new(2, 0);

        loop {
            if !signal::is_running() {
                // TODO: 清理系统配置
                break;
            }

            if let Err(_) = poll.poll(&mut events, Some(timeout)) {
                continue;
            }
            
            for event in events.iter() {
                match event.token() {
                    UDP_TOKEN => {
                        let (amt, remote_socket_addr) = self.udp_socket.recv_from(&mut self.buffer)?;
                        let remote_socket_addr = match remote_socket_addr {
                            SocketAddr::V4(v4_addr) => v4_addr,
                            _ => unreachable!(),
                        };

                        if amt < 4 {
                            continue;
                        }

                        let packet_signature = [
                            self.buffer[0], self.buffer[1], 
                            self.buffer[2], self.buffer[3], 
                        ];

                        match packet_signature {
                            DHCP_REQ_PACKET_SIGNATURE => {
                                // VPN 客户端请求分配内网地址
                                self.handle_dhcp_req(remote_socket_addr)?;
                                continue;
                            },
                            DHCP_RES_PACKET_SIGNATURE => {
                                continue;
                            },
                            TUNNEL_PACKET_SIGNATURE => {
                                self.handle_tunnel_pkt(remote_socket_addr, amt)?;
                                continue;
                            },
                            BYE_PACKET_SIGNATURE => {
                                let mut peer_tun_addr: Option<Ipv4Address> = None;

                                for (tun_ip, udp_addr) in &self.neighbor {
                                    if udp_addr == &remote_socket_addr {
                                        peer_tun_addr = Some(*tun_ip);
                                        break;
                                    }
                                }

                                if let Some(tun_addr) = peer_tun_addr {
                                    self.neighbor.remove(&tun_addr);
                                }
                                
                                continue;
                            },
                            _ => {
                                debug!("unknow packet signature: {:?}", packet_signature);
                                continue;
                            }
                        }
                    },
                    TUN_TOKEN => {
                        self.handle_tun_pkt()?;
                    },
                    _ => unreachable!(),
                }
            }
        }

        Ok(())
    }
}

