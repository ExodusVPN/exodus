use crate::socket::NetlinkSocket;
use crate::packet::Kind;
use crate::packet::NetlinkPacket;
use crate::packet::NetlinkErrorPacket;
use crate::packet::NetlinkAttrPacket;
use crate::packet::AddrPacket;
use crate::packet::AddrAttrType;
use crate::packet::AddrFlags;
use crate::packet::LinkName;
use crate::packet::RouteScope;
use crate::packet::AddressFamily;


use libc::IF_NAMESIZE;
use byteorder::{ByteOrder, NetworkEndian};

use std::io;


#[derive(Debug, Clone, Copy)]
pub struct Addr {
    pub ifindex: u32,
    pub flags: AddrFlags,
    pub scope: RouteScope,
    // Attrs
    pub addr: Option<std::net::IpAddr>,
    pub local: Option<std::net::IpAddr>,
    pub broadcast: Option<std::net::IpAddr>,
    pub label: Option<LinkName>,
}

pub struct Addrs<'a, 'b> {
    pub(crate) socket: &'a mut NetlinkSocket,
    pub(crate) buffer: &'b mut [u8],
    pub(crate) is_done: bool,
    pub(crate) buffer_len: usize,
    pub(crate) offset: usize,
}

impl<'a, 'b> Addrs<'a, 'b> {
    fn next_packet(&mut self) -> Result<Option<NetlinkPacket<&[u8]>>, io::Error> {
        if self.offset >= self.buffer_len {
            let amt = self.socket.recv(&mut self.buffer)?;
            trace!("read {} bytes from netlink socket.", amt);
            self.buffer_len = amt;
            self.offset = 0;
        }

        if self.buffer_len < NetlinkPacket::<&[u8]>::MIN_SIZE {
            return Ok(None);
        }

        let start = self.offset;
        let pkt = NetlinkPacket::new_checked(&self.buffer[self.offset..])?;
        let pkt_len = pkt.total_len();
        self.offset += pkt_len;
        let end = self.offset;

        let pkt = NetlinkPacket::new_unchecked(&self.buffer[start..end]);
        match pkt.kind() {
            Kind::NLMSG_NOOP     => Ok(None),
            Kind::NLMSG_ERROR    => Err(NetlinkErrorPacket::new_checked(pkt.payload())?.err()),
            Kind::NLMSG_DONE     => {
                self.is_done = true;
                Ok(None)
            },
            Kind::NLMSG_OVERRUN  => Err(io::Error::new(io::ErrorKind::InvalidData, "Overrun")),
            Kind::RTM_NEWADDR => Ok(Some(pkt)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, format!("Netlink Message Type is not `{:?}`", Kind::RTM_NEWADDR))),
        }
    }
}

impl<'a, 'b> Iterator for Addrs<'a, 'b> {
    type Item = Result<Addr, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done {
            return None;
        }

        let pkt = match self.next_packet() {
            Ok(Some(pkt)) => pkt,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        
        let packet = match AddrPacket::new_checked(pkt.payload()) {
            Ok(pkt) => pkt,
            Err(e) => return Some(Err(e)),
        };
        
        let address_family = packet.family();

        let ifindex = packet.ifindex() as u32;
        let flags = packet.flags();
        let scope = packet.scope();

        let mut addr = None;
        let mut local = None;
        let mut broadcast = None;
        let mut label = None;
        
        let mut payload = packet.payload();

        loop {
            if payload.len() < 4 {
                break;
            }

            let attr = match NetlinkAttrPacket::new_checked(&payload) {
                Ok(pkt) => pkt,
                Err(e) => return Some(Err(e)),
            };

            // let attr_payload_len = attr.payload_len();
            let attr_total_len = attr.total_len();

            let attr_kind = AddrAttrType(attr.kind());
            let attr_data = attr.payload();

            if attr_kind == AddrAttrType::IFA_LABEL {
                let mut _name = [0u8; IF_NAMESIZE];
                (&mut _name[..attr_data.len()]).copy_from_slice(&attr_data);
                label = Some(LinkName::new(_name, attr_data.len()));
            } else if attr_kind == AddrAttrType::IFA_ADDRESS {
                if address_family == AddressFamily::AF_INET {
                    let octets = NetworkEndian::read_u32(&attr_data);
                    addr = Some(std::net::Ipv4Addr::from(octets).into());
                } else if address_family == AddressFamily::AF_INET6 {
                    let octets = NetworkEndian::read_u128(&attr_data);
                    addr = Some(std::net::Ipv6Addr::from(octets).into())
                } else {
                    error!("Unknow Addr Attr: type={:15} data={:?}", format!("{:?}", attr_kind), attr_data);
                    continue;
                }
            } else if attr_kind == AddrAttrType::IFA_LOCAL {
                if address_family == AddressFamily::AF_INET {
                    let octets = NetworkEndian::read_u32(&attr_data);
                    local = Some(std::net::Ipv4Addr::from(octets).into());
                } else if address_family == AddressFamily::AF_INET6 {
                    let octets = NetworkEndian::read_u128(&attr_data);
                    local = Some(std::net::Ipv6Addr::from(octets).into())
                } else {
                    error!("Unknow Addr Attr: type={:15} data={:?}", format!("{:?}", attr_kind), attr_data);
                    continue;
                }
            } else if attr_kind == AddrAttrType::IFA_BROADCAST {
                if address_family == AddressFamily::AF_INET {
                    let octets = NetworkEndian::read_u32(&attr_data);
                    broadcast = Some(std::net::Ipv4Addr::from(octets).into());
                } else if address_family == AddressFamily::AF_INET6 {
                    let octets = NetworkEndian::read_u128(&attr_data);
                    broadcast = Some(std::net::Ipv6Addr::from(octets).into())
                } else {
                    error!("Unknow Addr Attr: type={:15} data={:?}", format!("{:?}", attr_kind), attr_data);
                    continue;
                }
            } else {
                // IFA_FLAGS
                // IFA_CACHEINFO
                trace!("Droped Addr Attr: type={:15} data={:?}", format!("{:?}", attr_kind), attr_data);
            }
            
            payload = &payload[attr_total_len..];
        }

        Some(Ok(Addr{ ifindex, flags, scope, addr, local, broadcast, label, }))
    }
}