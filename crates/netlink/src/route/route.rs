use crate::socket::NetlinkSocket;
use crate::packet::Kind;
use crate::packet::AddressFamily;
use crate::packet::NetlinkPacket;
use crate::packet::NetlinkErrorPacket;
use crate::packet::RoutePacket;
use crate::packet::NetlinkAttrPacket;
use crate::packet::RouteAttrType;
use crate::packet::{RouteTable, RouteProtocol, RouteScope, RouteType, RouteFlags};

use byteorder::{ByteOrder, NativeEndian, NetworkEndian};

use std::io;


#[derive(Debug, Clone, Copy)]
pub struct Route {
    pub table: RouteTable,
    pub protocol: RouteProtocol,
    pub scope: RouteScope,
    pub kind: RouteType,
    pub flags: RouteFlags,
    pub dst_addr: Option<std::net::IpAddr>,
    pub pref_src: Option<std::net::IpAddr>,
    pub out_ifindex: Option<u32>,
}

pub struct Routes<'a, 'b> {
    pub(crate) socket: &'a mut NetlinkSocket,
    pub(crate) buffer: &'b mut [u8],
    pub(crate) is_done: bool,
    pub(crate) buffer_len: usize,
    pub(crate) offset: usize,
}

impl<'a, 'b> Routes<'a, 'b> {
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
            Kind::RTM_NEWROUTE => Ok(Some(pkt)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, format!("Netlink Message Type is not `{:?}`", Kind::RTM_NEWROUTE))),
        }
    }
}

impl<'a, 'b> Iterator for Routes<'a, 'b> {
    type Item = Result<Route, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done {
            return None;
        }

        let pkt = match self.next_packet() {
            Ok(Some(pkt)) => pkt,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        
        let packet = match RoutePacket::new_checked(pkt.payload()) {
            Ok(pkt) => pkt,
            Err(e) => return Some(Err(e)),
        };
        
        let address_family = packet.family();
        let table = packet.table();
        let protocol = packet.protocol();
        let scope = packet.scope();
        let kind = packet.kind();
        let flags = packet.flags();
        let mut dst_addr = None;
        let mut pref_src = None;
        let mut out_ifindex = None;

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

            let attr_kind = RouteAttrType(attr.kind());
            let attr_data = attr.payload();
            
            if attr_kind == RouteAttrType::RTA_DST {
                if address_family == AddressFamily::AF_INET {
                    let octets = NetworkEndian::read_u32(&attr_data);
                    dst_addr = Some(std::net::Ipv4Addr::from(octets).into());
                } else if address_family == AddressFamily::AF_INET6 {
                    let octets = NetworkEndian::read_u128(&attr_data);
                    dst_addr = Some(std::net::Ipv6Addr::from(octets).into())
                } else {
                    error!("Unknow Route Attr: type={:15} data={:?}", format!("{:?}", attr_kind), attr_data);
                    continue;
                }
            } else if attr_kind == RouteAttrType::RTA_PREFSRC {
                if address_family == AddressFamily::AF_INET {
                    let octets = NetworkEndian::read_u32(&attr_data);
                    pref_src = Some(std::net::Ipv4Addr::from(octets).into());
                } else if address_family == AddressFamily::AF_INET6 {
                    let octets = NetworkEndian::read_u128(&attr_data);
                    pref_src = Some(std::net::Ipv6Addr::from(octets).into())
                } else {
                    error!("Unknow Route Attr: type={:15} data={:?}", format!("{:?}", attr_kind), attr_data);
                    continue;
                }
            } else if attr_kind == RouteAttrType::RTA_OIF {
                out_ifindex = Some(NativeEndian::read_i32(&attr_data) as u32);
            } else {
                trace!("Droped Route Attr: type={:15} data={:?}", format!("{:?}", attr_kind), attr_data);
            }
            
            payload = &payload[attr_total_len..];
        }

        Some(Ok(Route{ table, protocol, scope, kind, flags, dst_addr, pref_src, out_ifindex, }))
    }
}