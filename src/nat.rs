use smoltcp::wire::{ IpProtocol, Ipv4Packet, TcpPacket, UdpPacket, };

use std::io;
use std::collections::HashMap;
use std::os::unix::io::{ AsRawFd, FromRawFd, RawFd, };
use std::net::{ IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket, };



#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(u8)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Key {
    pub src_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_addr: Ipv4Addr,
    pub dst_port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Value {
    pub relay_port: u16,
    pub relay_raw_fd: RawFd,
}

pub struct Translation {
    relay_addr: Ipv4Addr,
    map: HashMap<Key, Value>,
}

impl Translation {
    pub fn new(relay_addr: Ipv4Addr) -> Self {
        let map = HashMap::new();

        Self { relay_addr, map }
    }
    
    pub fn relay_addr(&self) -> Ipv4Addr {
        self.relay_addr
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn translation(&mut self, mut packet: &mut [u8]) -> Result<(), io::Error> {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut packet);
        let src_addr = Ipv4Addr::from(ipv4_packet.src_addr());
        let dst_addr = Ipv4Addr::from(ipv4_packet.dst_addr());

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
                    let relay_raw_fd = value.relay_raw_fd;
                    let socket = unsafe { TcpListener::from_raw_fd(relay_raw_fd) };
                    // 检查该连接是否活跃
                    match socket.take_error() {
                        Ok(Some(_)) | Err(_) => {
                            let _ = self.map.remove(&key);
                        },
                        _ => {
                            relay_port = Some(value.relay_port);
                        },
                    }
                }

                if relay_port.is_none() {
                    let socket = TcpListener::bind(SocketAddrV4::new(self.relay_addr, 0))?;
                    let socket_addr = match socket.local_addr()? {
                        SocketAddr::V4(addr) => addr,
                        _ => unreachable!(),
                    };

                    let relay_port2 = socket_addr.port();
                    let relay_raw_fd = socket.as_raw_fd();
                    let value = Value { relay_port: relay_port2, relay_raw_fd, };

                    let _ = self.map.insert(key, value);
                    relay_port = Some(relay_port2);
                }

                tcp_packet.set_src_port(relay_port.unwrap());
                tcp_packet.fill_checksum(&IpAddr::from(self.relay_addr).into(), &IpAddr::from(dst_addr).into() );
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
                            let _ = self.map.remove(&key);
                        },
                        _ => {
                            relay_port = Some(value.relay_port);
                        },
                    }
                }

                if relay_port.is_none() {
                    let socket = UdpSocket::bind(SocketAddrV4::new(self.relay_addr, 0))?;
                    let socket_addr = match socket.local_addr()? {
                        SocketAddr::V4(addr) => addr,
                        _ => unreachable!(),
                    };

                    let relay_port2 = socket_addr.port();
                    let relay_raw_fd = socket.as_raw_fd();
                    let value = Value { relay_port: relay_port2, relay_raw_fd, };

                    let _ = self.map.insert(key, value);
                    relay_port = Some(relay_port2);
                }

                udp_packet.set_src_port(relay_port.unwrap());
                udp_packet.fill_checksum(&IpAddr::from(self.relay_addr).into(), &IpAddr::from(dst_addr).into());
                ipv4_packet.fill_checksum();

                Ok(())
            },
            _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
        }
    }
}

