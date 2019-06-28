use smoltcp::wire::{ IpProtocol, IpAddress, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket, };

use std::io;
use std::mem;
use std::collections::HashMap;
use std::os::unix::io::{ AsRawFd, FromRawFd, RawFd, };
use std::net::{ SocketAddr, SocketAddrV4, TcpListener, UdpSocket, };


#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(u8)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Key {
    pub src_addr: Ipv4Address,
    pub src_port: u16,
    pub dst_addr: Ipv4Address,
    pub dst_port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Value {
    pub relay_port: u16,
    pub relay_raw_fd: RawFd,
}

pub struct Translation {
    relay_addr: Ipv4Address,
    map: HashMap<Key, Value>,
    map2: HashMap<(Protocol, u16), Key>,
}

impl Translation {
    pub fn new(relay_addr: Ipv4Address) -> Self {
        let map = HashMap::new();
        let map2 = HashMap::new();

        Self { relay_addr, map, map2 }
    }
    
    pub fn relay_addr(&self) -> Ipv4Address {
        self.relay_addr
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    
    pub fn len(&self) -> usize {
        self.map.len()
    }
    
    pub fn is_mapped_port(&self, protocol: Protocol, relay_port: u16) -> bool {
        self.map2.contains_key(&(protocol, relay_port))
    }
    
    pub fn get_key(&self, protocol: Protocol, relay_port: u16) -> Option<&Key> {
        self.map2.get(&(protocol, relay_port))
    }

    pub fn get_value(&self, key: &Key) -> Option<&Value> {
        self.map.get(key)
    }

    pub fn contains_key(&self, key: &Key) -> bool {
        self.map.contains_key(key)
    }
    
    /// 还原数据包
    pub fn demasquerading(&mut self, mut packet: &mut [u8]) -> Result<(), io::Error> {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut packet);
        let src_addr = ipv4_packet.src_addr();
        
        match ipv4_packet.protocol() {
            IpProtocol::Tcp => {
                let payload = ipv4_packet.payload_mut();
                
                let mut tcp_packet = TcpPacket::new_unchecked(payload);
                let dst_port = tcp_packet.dst_port();
                
                match self.get_key(Protocol::Tcp, dst_port) {
                    Some(key) => {
                        // 复原数据包
                        tcp_packet.set_dst_port(key.src_port);
                        tcp_packet.fill_checksum(&IpAddress::from(src_addr), &IpAddress::from(key.src_addr).into() );
                        ipv4_packet.set_dst_addr(key.src_addr.into());
                        // NOTE: 暂不清楚是否可以省去校验码的工作，猜测这个工作应该是在驱动层完成的，内核协议栈应该不会去检查这个。
                        //       这个需要带确认。
                        ipv4_packet.fill_checksum();

                        Ok(())
                    },
                    None => {
                        // 该连接没有被映射
                        Err(io::Error::from(io::ErrorKind::NotFound))
                    }
                }
            },
            IpProtocol::Udp => {
                let payload = ipv4_packet.payload_mut();
                let mut udp_packet = UdpPacket::new_unchecked(payload);
                let dst_port = udp_packet.dst_port();
                
                match self.get_key(Protocol::Udp, dst_port) {
                    Some(key) => {
                        // 复原数据包
                        udp_packet.set_dst_port(key.src_port);
                        udp_packet.fill_checksum(&IpAddress::from(src_addr), &IpAddress::from(key.src_addr));
                        ipv4_packet.set_dst_addr(key.src_addr.into());
                        // NOTE: 暂不清楚是否可以省去校验码的工作，猜测这个工作应该是在驱动层完成的，内核协议栈应该不会去检查这个。
                        //       这个需要带确认。
                        ipv4_packet.fill_checksum();

                        Ok(())
                    },
                    None => {
                        // 该连接没有被映射
                        Err(io::Error::from(io::ErrorKind::NotFound))
                    }
                }
            },
            _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
        }
    }

    /// 映射/伪装 数据包
    pub fn masquerading(&mut self, mut packet: &mut [u8]) -> Result<(), io::Error> {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut packet);
        let src_addr = ipv4_packet.src_addr();
        let dst_addr = ipv4_packet.dst_addr();

        match ipv4_packet.protocol() {
            IpProtocol::Tcp => {
                let protocol = Protocol::Tcp;
                ipv4_packet.set_src_addr(self.relay_addr.into());
                
                let mut ipv4_packet = Ipv4Packet::new_unchecked(ipv4_packet.into_inner());
                let payload = ipv4_packet.payload_mut();
                
                let mut tcp_packet = TcpPacket::new_unchecked(payload);
                let src_port = tcp_packet.src_port();
                let dst_port = tcp_packet.dst_port();
                
                let key = Key {
                    src_addr, src_port,
                    dst_addr, dst_port,
                    protocol,
                };

                let mut relay_port = None;
                if let Some(value) = self.map.get(&key) {
                    // 该连接已被映射
                    let relay_raw_fd = value.relay_raw_fd;
                    let socket = unsafe { TcpListener::from_raw_fd(relay_raw_fd) };
                    // 检查该连接是否活跃
                    match socket.take_error() {
                        Ok(Some(_)) | Err(_) => {
                            let _ = self.map2.remove(&(protocol, value.relay_port));
                            let _ = self.map.remove(&key);
                            // 关闭文件描述符
                            drop(socket);
                        },
                        _ => {
                            relay_port = Some(value.relay_port);
                        },
                    }
                }

                if relay_port.is_none() {
                    // 为该连接创建映射
                    let socket = TcpListener::bind(SocketAddrV4::new(self.relay_addr.into(), 0))?;
                    let socket_addr = match socket.local_addr()? {
                        SocketAddr::V4(addr) => addr,
                        _ => unreachable!(),
                    };

                    let relay_port2 = socket_addr.port();
                    let relay_raw_fd = socket.as_raw_fd();
                    let value = Value { relay_port: relay_port2, relay_raw_fd, };

                    let _ = self.map.insert(key, value);
                    relay_port = Some(relay_port2);
                    let _ = self.map2.insert((protocol, relay_port2), key);

                    // 避免 Rust 自动关闭该文件描述符
                    mem::forget(socket);
                }

                tcp_packet.set_src_port(relay_port.unwrap());
                tcp_packet.fill_checksum(&IpAddress::from(self.relay_addr), &IpAddress::from(dst_addr));
                ipv4_packet.fill_checksum();

                Ok(())
            },
            IpProtocol::Udp => {
                let protocol = Protocol::Udp;
                ipv4_packet.set_src_addr(self.relay_addr.into());
                
                let mut ipv4_packet = Ipv4Packet::new_unchecked(ipv4_packet.into_inner());
                let payload = ipv4_packet.payload_mut();
                
                let mut udp_packet = UdpPacket::new_unchecked(payload);
                let src_port = udp_packet.src_port();
                let dst_port = udp_packet.dst_port();
                
                let key = Key {
                    src_addr, src_port,
                    dst_addr, dst_port,
                    protocol,
                };
                
                let mut relay_port = None;
                if let Some(value) = self.map.get(&key) {
                    let relay_raw_fd = value.relay_raw_fd;
                    let socket = unsafe { UdpSocket::from_raw_fd(relay_raw_fd) };
                    // 检查该连接是否活跃
                    match socket.take_error() {
                        Ok(Some(_)) | Err(_) => {
                            let _ = self.map2.remove(&(protocol, value.relay_port));
                            let _ = self.map.remove(&key);
                            // 关闭文件描述符
                            drop(socket);
                        },
                        _ => {
                            relay_port = Some(value.relay_port);
                        },
                    }
                }

                if relay_port.is_none() {
                    let socket = UdpSocket::bind(SocketAddrV4::new(self.relay_addr.into(), 0))?;
                    let socket_addr = match socket.local_addr()? {
                        SocketAddr::V4(addr) => addr,
                        _ => unreachable!(),
                    };

                    let relay_port2 = socket_addr.port();
                    let relay_raw_fd = socket.as_raw_fd();
                    let value = Value { relay_port: relay_port2, relay_raw_fd, };

                    let _ = self.map.insert(key, value);
                    relay_port = Some(relay_port2);
                    let _ = self.map2.insert((protocol, relay_port2), key);

                    // 避免 Rust 自动关闭该文件描述符
                    mem::forget(socket);
                }

                udp_packet.set_src_port(relay_port.unwrap());
                udp_packet.fill_checksum(&IpAddress::from(self.relay_addr), &IpAddress::from(dst_addr));
                ipv4_packet.fill_checksum();

                Ok(())
            },
            _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
        }
    }
}


#[test]
fn test_tcp() {
    let mut buffer = [0u8; 1500];
    let mut packet = &mut buffer[..];

    let make_packet = |mut packet: &mut [u8], src_addr: Ipv4Address, src_port: u16, dst_addr: Ipv4Address, dst_port: u16| {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut packet);
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_len(20);
        ipv4_packet.set_total_len(1000);
        ipv4_packet.set_protocol(IpProtocol::Tcp);
        
        let payload = ipv4_packet.payload_mut();

        let mut tcp_packet = TcpPacket::new_unchecked(payload);
        tcp_packet.set_src_port(src_port);
        tcp_packet.set_dst_port(dst_port);

        ipv4_packet.set_src_addr(src_addr.into());
        ipv4_packet.set_dst_addr(dst_addr.into());
    };

    let relay_addr = "127.0.0.1".parse::<Ipv4Address>().unwrap();
    let mut nat = Translation::new(relay_addr);

    let src_addr = "127.0.0.1".parse::<Ipv4Address>().unwrap();
    let src_port = 3000u16;
    let dst_addr = "8.8.8.8".parse::<Ipv4Address>().unwrap();
    let dst_port = 443u16;
    let protocol = Protocol::Tcp;

    make_packet(&mut packet, src_addr, src_port, dst_addr, dst_port);
    assert!(nat.masquerading(&mut packet).is_ok());;

    let key = Key {
        src_addr, src_port,
        dst_addr, dst_port,
        protocol,
    };
    let value = nat.get_value(&key);
    assert!(value.is_some());
    let relay_port = value.unwrap().relay_port;

    make_packet(&mut packet, dst_addr, dst_port, relay_addr, relay_port);
    assert!(nat.demasquerading(&mut packet).is_ok());;

    // Check
    let ipv4_packet = Ipv4Packet::new_unchecked(&packet);
    assert_eq!(ipv4_packet.src_addr(), dst_addr.into());
    assert_eq!(ipv4_packet.dst_addr(), src_addr.into());

    let payload = ipv4_packet.payload();
    let tcp_packet = TcpPacket::new_unchecked(payload);
    assert_eq!(tcp_packet.src_port(), dst_port);
    assert_eq!(tcp_packet.dst_port(), src_port);
}

#[test]
fn test_udp() {
    let mut buffer = [0u8; 1500];
    let mut packet = &mut buffer[..];

    let make_packet = |mut packet: &mut [u8], src_addr: Ipv4Address, src_port: u16, dst_addr: Ipv4Address, dst_port: u16| {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut packet);
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_len(20);
        ipv4_packet.set_total_len(1000);
        ipv4_packet.set_protocol(IpProtocol::Udp);
        
        let payload = ipv4_packet.payload_mut();

        let mut udp_packet = UdpPacket::new_unchecked(payload);
        udp_packet.set_src_port(src_port);
        udp_packet.set_dst_port(dst_port);

        ipv4_packet.set_src_addr(src_addr.into());
        ipv4_packet.set_dst_addr(dst_addr.into());
    };

    let relay_addr = "127.0.0.1".parse::<Ipv4Address>().unwrap();
    let mut nat = Translation::new(relay_addr);

    let src_addr = "127.0.0.1".parse::<Ipv4Address>().unwrap();
    let src_port = 3000u16;
    let dst_addr = "8.8.8.8".parse::<Ipv4Address>().unwrap();
    let dst_port = 443u16;
    let protocol = Protocol::Udp;

    make_packet(&mut packet, src_addr, src_port, dst_addr, dst_port);
    assert!(nat.masquerading(&mut packet).is_ok());;

    let key = Key {
        src_addr, src_port,
        dst_addr, dst_port,
        protocol,
    };
    let value = nat.get_value(&key);
    assert!(value.is_some());
    let relay_port = value.unwrap().relay_port;

    make_packet(&mut packet, dst_addr, dst_port, relay_addr, relay_port);
    assert!(nat.demasquerading(&mut packet).is_ok());;
    
    // Check
    let ipv4_packet = Ipv4Packet::new_unchecked(&packet);
    assert_eq!(ipv4_packet.src_addr(), dst_addr.into());
    assert_eq!(ipv4_packet.dst_addr(), src_addr.into());

    let payload = ipv4_packet.payload();
    let udp_packet = UdpPacket::new_unchecked(payload);
    assert_eq!(udp_packet.src_port(), dst_port);
    assert_eq!(udp_packet.dst_port(), src_port);
}
