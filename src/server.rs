use mio;
use znet;
use znet::raw_socket::{BufferReader, LinkLayer, RawSocket};
use smoltcp::wire::{
    PrettyPrinter,
    EthernetAddress, EthernetFrame, EthernetProtocol,
    IpProtocol, IpVersion,
    Ipv4Cidr, Ipv4Address, Ipv4Packet,
    TcpPacket, UdpPacket,
};

use crate::nat;
use crate::signal;


use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::net::{ IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket, };


const EXODUS_VPN_IP_PROTOCOL_DHCP: IpProtocol = IpProtocol::Unknown(197);
const EXODUS_VPN_IP_PROTOCOL_ICMP: IpProtocol = IpProtocol::Unknown(198);
const EXODUS_VPN_IP_PROTOCOL_TCP: IpProtocol  = IpProtocol::Unknown(199);
const EXODUS_VPN_IP_PROTOCOL_UDP: IpProtocol  = IpProtocol::Unknown(200);


const TAP_TOKEN: mio::Token    = mio::Token(10);
const TUN_TOKEN: mio::Token    = mio::Token(11);
const UDP_TOKEN: mio::Token    = mio::Token(12);
const VPN_SERVER_TOKEN: mio::Token  = mio::Token(13);
const VPN_CLIENT_TOKEN: mio::Token  = mio::Token(14);
const DHCP_SERVER_TOKEN: mio::Token = mio::Token(15);


const DEFAULT_VPN_SERVER_TUNNEL_PORT: u16  = 9050;
const DEFAULT_VPN_SERVER_DHCP_PORT: u16    = 9051;


#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum InterfaceKind {
    Ethernet,
    // TAP Interface
    Internet,
}


pub const DHCP_REQ_PACKET_SIGNATURE: [u8; 4] = [255, 255, 255, 200];
pub const DHCP_RES_PACKET_SIGNATURE: [u8; 4] = [255, 255, 255, 201];
// NOTE: 同时也是 macOS 系统里面 TUN 的 IPv4Packet 签名
pub const TUNNEL_PACKET_SIGNATURE: [u8; 4]   = [000, 000, 000, 002];
pub const BYE_PACKET_SIGNATURE: [u8; 4]      = [255, 255, 255, 255];


#[derive(Debug, Clone)]
pub struct VpnServerConfig {
    pub tun_ifname: String,
    pub tun_cidr: Ipv4Cidr,
    pub egress_iface_kind: InterfaceKind,
    pub egress_iface_name: String,
    pub egress_iface_addr: Ipv4Address,

    // NOTE: 如果 `egress_iface_kind` 设置为了 以太网 模式
    //       那么下面的三个 选项参数都必须提供！
    pub egress_iface_hwaddr: Option<EthernetAddress>,
    pub egress_iface_gateway_addr: Option<Ipv4Address>,
    pub egress_iface_gateway_hwaddr: Option<EthernetAddress>,
    pub tunnel_service_udp_port: u16,
    // pub dhcp_service_udp_port: u16,
}

pub type TunDevice = tun::platform::Device;

pub struct VpnServer {
    config  :        VpnServerConfig,
    tun_addr:        Ipv4Address,
    tun_netmask:     Ipv4Address,
    dhcp_start_addr: u32,
    dhcp_end_addr:   u32,
    dhcp_next_addr:  u32,
    neighbor  :      HashMap<Ipv4Address, SocketAddrV4>,
    nat:             nat::Translation,
    buffer:          [u8; 2048],
    tun_device:      TunDevice,
    egress_device:   znet::raw_socket::RawSocket,
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

        let mut tun_device: TunDevice = tun::create(
            tun::Configuration::default()
                .address(tun_addr)
                    .netmask(tun_netmask)
                    .destination(Ipv4Addr::new(0, 0, 0, 0))
                    .mtu(1500)
                    .name(&config.tun_ifname)
                    .up())
            .map_err(|e| {
                match e.0 {
                    tun::ErrorKind::Io(ioerror)       => ioerror,
                    tun::ErrorKind::Msg(s)            => io::Error::new(io::ErrorKind::InvalidInput, s.clone()),
                    tun::ErrorKind::Nul(nul_err)      => io::Error::new(io::ErrorKind::InvalidData, nul_err.clone()),
                    tun::ErrorKind::ParseNum(pe)      => io::Error::new(io::ErrorKind::InvalidData, pe),
                    tun::ErrorKind::NameTooLong       => io::Error::new(io::ErrorKind::InvalidData, "name too long"),
                    tun::ErrorKind::InvalidAddress    => io::Error::from(io::ErrorKind::AddrNotAvailable),
                    tun::ErrorKind::InvalidDescriptor => io::Error::from(io::ErrorKind::NotConnected),
                    _ => unreachable!(),
                }
            })?;

        // NOTE:
        // 这里需要为系统配置 静态路由
        // Linux
        //      sudo route add -net 172.16.0.0/16  dev utun10
        // macOS
        //      sudo route add -net 172.16.0.0/16 -interface utun8
        // 
        // 在未来，这个会通过 C 库自动实现
        // 目前临时使用 命令行程序 去配置这些数据

        warn!("为系统路由表添加静态路由:
        Linux: sudo route add -net {}  dev {}
        macOS: sudo route add -net {} -interface {}",
        tun_cidr, &config.tun_ifname,
        tun_cidr, &config.tun_ifname,);

        std::thread::sleep(std::time::Duration::new(2, 0));

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

        let mut egress_device = znet::raw_socket::RawSocket::with_ifname(&config.egress_iface_name)?;
        let mut translation = nat::Translation::new(config.egress_iface_addr);

        let sa = SocketAddrV4::new(config.egress_iface_addr.into(), config.tunnel_service_udp_port);
        let mut udp_socket = mio::net::UdpSocket::bind(&sa.into())?;

        // std::thread::sleep(std::time::Duration::new(2, 0));

        Ok(VpnServer {
            config,
            tun_addr: tun_addr.into(),
            tun_netmask: tun_netmask.into(),
            dhcp_start_addr,
            dhcp_end_addr,
            dhcp_next_addr,
            neighbor: HashMap::new(),
            nat: translation,
            buffer: [0u8; 2048],
            tun_device,
            egress_device,
            udp_socket,
        })
    }

    pub fn run_forever(&mut self) -> Result<(), io::Error> {
        let mut events = mio::Events::with_capacity(1024);
        let poll = mio::Poll::new().unwrap();

        let egress_device_raw_fd = self.egress_device.as_raw_fd();
        let egress_device = mio::unix::EventedFd(&egress_device_raw_fd);

        poll.register(&egress_device, TAP_TOKEN, mio::Ready::readable(), mio::PollOpt::edge())?;
        poll.register(&self.tun_device, TUN_TOKEN, mio::Ready::readable(), mio::PollOpt::edge())?;
        poll.register(&self.udp_socket, UDP_TOKEN, mio::Ready::readable(), mio::PollOpt::edge())?;

        let timeout = std::time::Duration::new(2, 0);

        loop {
            if !signal::is_running() {
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

                        let packet_signature = [
                            self.buffer[0], self.buffer[1], 
                            self.buffer[2], self.buffer[3], 
                        ];

                        let packet = &self.buffer[4..amt];

                        match packet_signature {
                            DHCP_REQ_PACKET_SIGNATURE => {
                                // VPN 客户端请求分配内网地址
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
                                (&mut self.buffer[..4]).copy_from_slice(&DHCP_RES_PACKET_SIGNATURE);
                                (&mut self.buffer[4..8]).copy_from_slice(&dhcp_addr.0);

                                (&mut self.buffer[8..12]).copy_from_slice(&self.tun_addr.0);
                                (&mut self.buffer[12..16]).copy_from_slice(&self.tun_netmask.0);

                                let message = &self.buffer[..8];
                                self.udp_socket.send_to(&message, &(remote_socket_addr.into()))?;
                                
                                if dhcp_addr != Ipv4Address::UNSPECIFIED {
                                    debug!("为 {} 分配虚拟地址: {}", remote_socket_addr, dhcp_addr);
                                    self.neighbor.insert(dhcp_addr, remote_socket_addr);
                                }
                            },
                            DHCP_RES_PACKET_SIGNATURE => {
                                continue;
                            },
                            TUNNEL_PACKET_SIGNATURE => {
                                let ipv4_packet = Ipv4Packet::new_unchecked(&packet);
                                let src_ip = ipv4_packet.src_addr();
                                let dst_ip = ipv4_packet.dst_addr();

                                // 确保要送达的地址的不是 发送者自己 以及 VPN 服务器
                                // TODO:
                                // 

                                if self.config.tun_cidr.contains_addr(&dst_ip) {
                                    // 子网路由，直接发送，不需要经过 TUN 设备中继
                                    // TODO: 以后需要增加身份认证机制
                                    if let Some(remote_addr) = self.neighbor.get(&dst_ip) {
                                        let message = &self.buffer[..packet.len() + 4];
                                        let addr = (*remote_addr).into();
                                        // NOTE: 这里的错误不再需要处理
                                        let _ = self.udp_socket.send_to(&message, &addr);
                                    }
                                } else {
                                    // 确保是 公网地址
                                    let is_global_ip = 
                                           !dst_ip.is_loopback() 
                                        && !dst_ip.is_link_local()
                                        && !dst_ip.is_broadcast()
                                        // && !dst_ip.is_documentation()
                                        && !dst_ip.is_unspecified();

                                    if is_global_ip {
                                        #[cfg(target_os = "linux")]
                                        self.tun_device.write(&packet)?;

                                        #[cfg(target_os = "macos")]
                                        self.tun_device.write(&self.buffer[..packet.len() + 4])?;
                                    }
                                }
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
                                continue;
                            }
                        }
                    },
                    TUN_TOKEN => {
                        #[cfg(target_os = "macos")]
                        let amt = self.tun_device.read(&mut self.buffer)?;

                        // NOTE: Linux 的 TUN 设备默认设置了 IFF_NO_PI 标志
                        //       没有携带 Packet Infomation，所以这里我们给它预留 4 个 Bytes 空间
                        #[cfg(target_os = "linux")]
                        self.buffer.copy_from_slice(&TUNNEL_PACKET_SIGNATURE);
                        #[cfg(target_os = "linux")]
                        let amt = self.tun_device.read(&mut self.buffer[4..])?;
                        
                        if amt <= 4 {
                            // NOTE: 畸形数据包，这里我们直接忽略
                            continue;
                        }

                        let packet_signature = [
                            self.buffer[0], self.buffer[1], 
                            self.buffer[2], self.buffer[3], 
                        ];

                        #[cfg(target_os = "macos")]
                        assert_eq!(packet_signature, TUNNEL_PACKET_SIGNATURE);

                        let mut packet = &mut self.buffer[4..amt + 4];

                        match IpVersion::of_packet(&packet) {
                            Ok(IpVersion::Ipv4) => { },
                            Ok(IpVersion::Ipv6) => continue, // NOTE: 暂不支持处理 IPv6
                            _                   => continue,
                        }

                        let ipv4_packet = Ipv4Packet::new_unchecked(&packet);
                        let ipv4_protocol = ipv4_packet.protocol();
                        let dst_ip = ipv4_packet.dst_addr();
                        
                        // 路由机制
                        match self.neighbor.get(&dst_ip) {
                            Some(brother_udp_socket_addr) => {
                                //       如果该包是传递给 Tun Network 成员的
                                //       则直接通过该 地址对应的 UDP 地址发送出去
                                let addr = std::net::SocketAddr::from(*brother_udp_socket_addr);
                                self.udp_socket.send_to(&packet, &addr)?;
                            },
                            None => {
                                // NOTE: 地址转换映射 (NAT)
                                // 目标地址 在 TUN Network 之外
                                // 这里需要做地址转换
                                // 如果使用操作系统的转换机制，那么在 Linux 下可以使用 iptables
                                // 在 macOS 下面使用 pfctl 之类的防火墙工具
                                // 
                                // 示例:
                                // Linux: 
                                //      sudo iptables -t nat -A POSTROUTING -s 172.16.10.1/24 -o enp0s3 -j MASQUERADE
                                //      sudo iptables -A OUTPUT -o utun10 -j ACCEPT
                                // macOS: 
                                //      sudo pfctl -s state
                                //      sudo pfctl -s nat
                                //      https://www.openbsd.org/faq/pf/nat.html
                                // 
                                // 注意: 大部分时候你使用操作系统防火墙做 地址转换(NAT) 时，需要预先配置系统的转发规则设定
                                // Linux
                                //      sudo sysctl net.ipv4.ip_forward=1
                                //      sudo sysctl net.ipv4.conf.all.forwarding=1  # 注: 上面这条 路径被广泛使用
                                //      sudo sysctl net.ipv6.conf.all.forwarding=1
                                // macOS
                                //      sudo sysctl net.inet.ip.forwarding=1
                                //      sudo sysctl net.inet6.ip6.forwarding=1
                                //
                                // 当然，我们 ExodusVPN 实现了自己的 NAT 映射表，所以我们不再需要使用操作系统自带的防火墙机制
                                
                                // 步骤一: 地址转换（NAT）
                                self.nat.masquerading(&mut packet)?;
                                // 步骤二: 当前的 Packet 数据中的来源地址已经被修改
                                //        现在我们通过 RawSocket 把这份 Packet 通过默认的 NetInterface 发送出去
                                match self.egress_device.link_layer() {
                                    LinkLayer::IpWithPI(prefix_len) => {
                                        // 流量出口设备为 TUN 类型的设备
                                        // WARN:
                                        //      考虑到这种网络环境极其少见
                                        //      所以这里不再考虑实现它
                                        unimplemented!()
                                    },
                                    LinkLayer::Eth => {
                                        // 流量出口设备为以太网设备
                                        // NOTE:
                                        //      由于我们的 TUN 设备里面传递的是 IP 层数据包
                                        //      所以这个时候我们需要组装出一个以太网数据包(EthernetFrame)
                                        const ETH_HDR_LEN: usize = 14;
                                        assert_eq!(packet.len() <= 1500, true);
                                        
                                        let mut eth_packet = [0u8; 1500 + ETH_HDR_LEN];
                                        &mut eth_packet[ETH_HDR_LEN..].copy_from_slice(&packet);

                                        let eth_packet_len = packet.len() + ETH_HDR_LEN;

                                        let mut ethernet_frame = EthernetFrame::new_unchecked(&mut eth_packet[..]);
                                        ethernet_frame.set_src_addr(self.config.egress_iface_hwaddr.unwrap());
                                        ethernet_frame.set_dst_addr(self.config.egress_iface_gateway_hwaddr.unwrap());
                                        ethernet_frame.set_ethertype(EthernetProtocol::Ipv4);

                                        self.egress_device.send(&eth_packet[..eth_packet_len])?;
                                    },
                                    LinkLayer::Ip => {
                                        // 流量出口设备为因特网设备
                                        // NOTE:
                                        //      这种网络环境在个人用户当中相当少见，
                                        //      一般出现在一些小型的 VPS 提供商当中
                                        //      如: 搬瓦工 VPS
                                        self.egress_device.send(&packet)?;
                                    },
                                }
                            },
                        }
                    },
                    TAP_TOKEN => {
                        // 检查流量出口设备中的传入流量是否有送达 TUN Device 的流量
                        let amt = self.egress_device.recv(&mut self.buffer)?;
                        for (start, end) in BufferReader::new(&self.buffer, amt) {
                            match self.egress_device.link_layer() {
                                LinkLayer::IpWithPI(prefix_len) => {
                                    let packet = &self.buffer[start+prefix_len..end];
                                    unimplemented!()
                                },
                                LinkLayer::Eth => {
                                    let mut packet = &self.buffer[start..end];
                                    let ethernet_frame = EthernetFrame::new_unchecked(&packet);

                                    trace!("{}",PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &ethernet_frame));

                                    let ipv4_packet = Ipv4Packet::new_unchecked(ethernet_frame.payload());
                                    let (protocol, dst_port) = match ipv4_packet.protocol() {
                                        IpProtocol::Tcp => {
                                            let payload = ipv4_packet.payload();
                                            let tcp_packet = TcpPacket::new_unchecked(payload);
                                            // let src_port = tcp_packet.src_port();
                                            let dst_port = tcp_packet.dst_port();

                                            (nat::Protocol::Tcp, dst_port)
                                        },
                                        _ => {
                                            continue;
                                        },
                                    };

                                    // 步骤一: 检查该端口是否被 地址转换（NAT）服务转换过
                                    if !self.nat.is_mapped_port(protocol, dst_port) {;
                                        continue;
                                    }

                                    let packet_len = packet.len();
                                    let mut packet = unsafe { std::slice::from_raw_parts_mut(packet.as_ptr() as *mut _, packet_len) };
                                    // 步骤二: 地址复原
                                    self.nat.demasquerading(&mut packet)?;

                                    println!("NATs: {:?}", self.nat.len());

                                    // 步骤三: 写入 TUN 设备
                                    assert_eq!(packet_len <= 1500, true);
                                        
                                    let mut tun_packet = [0u8; 2048];
                                    
                                    &mut tun_packet[..4].copy_from_slice(&TUNNEL_PACKET_SIGNATURE);
                                    &mut tun_packet[4..packet_len+4].copy_from_slice(&packet);

                                    #[cfg(target_os = "linux")]
                                    self.tun_device.write(&tun_packet[4..packet_len+4])?;

                                    #[cfg(target_os = "macos")]
                                    self.tun_device.write(&tun_packet[..packet_len+4])?;
                                },
                                LinkLayer::Ip => {
                                    let packet = &self.buffer[start..end];
                                    let ipv4_packet = Ipv4Packet::new_unchecked(&packet);
                                    let (protocol, dst_port) = match ipv4_packet.protocol() {
                                        IpProtocol::Tcp => {
                                            let payload = ipv4_packet.payload();
                                            let tcp_packet = TcpPacket::new_unchecked(payload);
                                            // let src_port = tcp_packet.src_port();
                                            let dst_port = tcp_packet.dst_port();

                                            (nat::Protocol::Tcp, dst_port)
                                        },
                                        _ => {
                                            continue;
                                        },
                                    };

                                    // 步骤一: 检查该端口是否被 地址转换（NAT）服务转换过
                                    if !self.nat.is_mapped_port(protocol, dst_port) {;
                                        continue;
                                    }

                                    let packet_len = packet.len();
                                    let mut packet = unsafe { std::slice::from_raw_parts_mut(packet.as_ptr() as *mut _, packet_len) };
                                    // 步骤二: 地址复原
                                    self.nat.demasquerading(&mut packet)?;

                                    debug!("NATs: {:?}", self.nat.len());

                                    // 步骤三: 写入 TUN 设备
                                    assert_eq!(packet_len <= 1500, true);
                                        
                                    let mut tun_packet = [0u8; 2048];
                                    
                                    &mut tun_packet[..4].copy_from_slice(&TUNNEL_PACKET_SIGNATURE);
                                    &mut tun_packet[4..packet_len+4].copy_from_slice(&packet);
                                    
                                    #[cfg(target_os = "linux")]
                                    self.tun_device.write(&tun_packet[4..packet_len+4])?;
                                    
                                    #[cfg(target_os = "macos")]
                                    self.tun_device.write(&tun_packet[..packet_len+4])?;
                                }
                            }
                        }
                    },
                    n => {
                        warn!("Unknow Token: {:?}", n);
                    }
                }
            }
        }

        Ok(())
    }
}

