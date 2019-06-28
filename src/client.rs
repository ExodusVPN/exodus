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


const TAP_TOKEN: mio::Token    = mio::Token(10);
const TUN_TOKEN: mio::Token    = mio::Token(11);
const UDP_TOKEN: mio::Token    = mio::Token(12);


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
pub struct VpnClientConfig {
    pub tun_ifname: String,
    pub egress_iface_addr: Ipv4Address,
    pub egress_iface_gateway_addr: Ipv4Address,
    pub vpn_server_addr: Ipv4Address,
    pub vpn_server_port: u16,
}

pub type TunDevice = tun::platform::Device;

#[derive(Debug, Clone)]
pub struct DhcpState {
    tun_addr        : Ipv4Address,
    tun_gateway_addr: Ipv4Address,
    tun_netmask     : Ipv4Address,
}

pub struct VpnClient {
    config     : VpnClientConfig,
    dhcp_state : DhcpState,
    buffer     : [u8; 2048],
    tun_device : TunDevice,
    udp_socket : mio::net::UdpSocket,
}

impl VpnClient {
    fn dhcp_request(config: &VpnClientConfig, udp_socket: &mut mio::net::UdpSocket) -> Result<DhcpState, io::Error> {
        let server_addr = &SocketAddrV4::new(config.vpn_server_addr.into(), config.vpn_server_port).into();
        udp_socket.send_to(&DHCP_REQ_PACKET_SIGNATURE, &server_addr)?;

        let mut buffer = [0u8; 2048];
        loop {
            debug!("try recv dhcp response ...");

            if !signal::is_running() {
                std::process::exit(0);
            }

            match udp_socket.recv_from(&mut buffer) {
                Ok((amt, peer_addr)) => {
                    if server_addr != &peer_addr {
                        continue;
                    }
                    
                    let packet_signature = [
                        buffer[0], buffer[1], 
                        buffer[2], buffer[3], 
                    ];
                    
                    if amt < 16 || packet_signature != DHCP_RES_PACKET_SIGNATURE {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "DHCP 失败: 未知协议！"))
                    }

                    let tun_addr = Ipv4Address::from_bytes(&buffer[4..8]);
                    if tun_addr == Ipv4Address::UNSPECIFIED {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "DHCP 失败: 无可用地址！"))
                    }

                    let tun_gateway_addr = Ipv4Address::from_bytes(&buffer[8..12]);
                    let tun_netmask = Ipv4Address::from_bytes(&buffer[12..16]);

                    return Ok(DhcpState{ tun_addr, tun_gateway_addr, tun_netmask, });
                },
                Err(e) => {
                    match e.kind() {
                        io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(200));
                            continue;
                        },
                        _ => return Err(e),
                    }
                },
            }

        }
    }

    pub fn new(config: VpnClientConfig) -> Result<Self, io::Error> {
        // 172.16.0.0/16
        let local_addr: SocketAddr  = SocketAddrV4::new(config.egress_iface_addr.into(), 0).into();
        let server_addr: SocketAddr = SocketAddrV4::new(config.vpn_server_addr.into(), config.vpn_server_port).into();
        
        let mut udp_socket = mio::net::UdpSocket::bind(&local_addr)?;
        let local_addr1 = udp_socket.local_addr()?;
        info!("bind to {}", local_addr1);

        let dhcp_state = Self::dhcp_request(&config, &mut udp_socket)?;

        debug!("try connect to {} ...", server_addr);
        udp_socket.connect(server_addr)?;
        info!("connect to {} ...", server_addr);

        let local_addr2 = udp_socket.local_addr()?;
        // 确保前后地址一致
        assert_eq!(local_addr1, local_addr2);
        debug!("connected!");

        let mut tun_device: TunDevice = tun::create(
            tun::Configuration::default()
                .address(Ipv4Addr::from(dhcp_state.tun_addr))
                    .netmask(Ipv4Addr::from(dhcp_state.tun_netmask))
                    .destination(Ipv4Addr::from(dhcp_state.tun_gateway_addr))
                    .mtu(1500-30-4)
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
        //      sudo route add -net 172.16.0.0/16  dev utun9
        // macOS
        //      sudo route add -net 172.16.0.0/16 -interface utun8
        // 
        // 在未来，这个会通过 C 库自动实现
        // 目前临时使用 命令行程序 去配置这些数据
        let tun_cidr = Ipv4Cidr::from_netmask(dhcp_state.tun_addr, dhcp_state.tun_netmask).unwrap();
        warn!("为系统路由表添加静态路由:
        Linux: sudo route add -net {} dev {}
        macOS: sudo route add -net {} -interface {}",
        tun_cidr, &config.tun_ifname,
        tun_cidr, &config.tun_ifname,);
        
        std::thread::sleep(std::time::Duration::new(1, 0));

        Ok(VpnClient {
            config,
            dhcp_state,
            buffer: [0u8; 2048],
            tun_device,
            udp_socket,
        })
    }

    pub fn run_forever(&mut self) -> Result<(), io::Error> {
        let mut events = mio::Events::with_capacity(1024);
        let poll = mio::Poll::new().unwrap();

        poll.register(&self.tun_device, TUN_TOKEN, mio::Ready::readable(), mio::PollOpt::edge())?;
        poll.register(&self.udp_socket, UDP_TOKEN, mio::Ready::readable(), mio::PollOpt::edge())?;

        let timeout = std::time::Duration::new(2, 0);

        loop {
            if !signal::is_running() {
                // 通知断开链接，不再需要处理错误
                let _ = self.udp_socket.send(&BYE_PACKET_SIGNATURE);
                // TODO: 清理系统配置
                break;
            }

            if let Err(_) = poll.poll(&mut events, Some(timeout)) {
                continue;
            }
            
            for event in events.iter() {
                match event.token() {
                    UDP_TOKEN => {
                        let amt = self.udp_socket.recv(&mut self.buffer)?;

                        if amt <= 4 {
                            // NOTE: 畸形数据包，这里我们直接忽略
                            debug!("畸形的数据包");
                            continue;
                        }

                        let packet_signature = [
                            self.buffer[0], self.buffer[1], 
                            self.buffer[2], self.buffer[3], 
                        ];

                        let packet = &self.buffer[4..amt];

                        match packet_signature {
                            DHCP_REQ_PACKET_SIGNATURE => {
                                debug!("DHCP Request packet signature.");
                                continue;
                            },
                            DHCP_RES_PACKET_SIGNATURE => {
                                debug!("DHCP Response packet signature.");
                                continue;
                            },
                            TUNNEL_PACKET_SIGNATURE => {
                                debug!("\n{}", PrettyPrinter::<Ipv4Packet<&[u8]>>::new("", &packet));

                                #[cfg(target_os = "macos")]
                                let packet = &self.buffer[..amt];
                                
                                debug!("{:?}", &packet);
                                self.tun_device.write(&packet)?;
                            },
                            BYE_PACKET_SIGNATURE => {
                                continue;
                            },
                            n => {
                                debug!("unknow packet signature: {:?}", n);
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
                        &mut self.buffer[..4].copy_from_slice(&TUNNEL_PACKET_SIGNATURE);
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

                        #[cfg(target_os = "linux")]
                        let mut packet = &self.buffer[4..amt + 4];
                        #[cfg(target_os = "macos")]
                        let mut packet = &self.buffer[4..amt];

                        match IpVersion::of_packet(&packet) {
                            Ok(IpVersion::Ipv4) => { },
                            Ok(IpVersion::Ipv6) => continue, // NOTE: 暂不支持处理 IPv6
                            _                   => continue,
                        }
                        // debug!("tun device send to udp socket.");
                        debug!("tun device send to udp socket:\n{}", PrettyPrinter::<Ipv4Packet<&[u8]>>::new("", &packet));
                        self.udp_socket.send(&self.buffer[..packet.len()+4])?;
                    },
                    _ => {
                        continue;
                    }
                }
            }
        }

        Ok(())
    }
}

