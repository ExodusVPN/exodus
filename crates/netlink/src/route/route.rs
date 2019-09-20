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
use smoltcp::wire::IpCidr;

use std::io;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};


#[derive(Debug, Clone, Copy)]
pub struct Route {
    pub table: RouteTable,
    pub protocol: RouteProtocol,
    pub scope: RouteScope,
    pub kind: RouteType,
    pub flags: RouteFlags,
    pub address_family: AddressFamily,
    pub dst_cidr: Option<IpCidr>,
    pub pref_src: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub out_ifindex: Option<u32>,
}

impl TryFrom<&[u8]> for Route {
    type Error = io::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let packet = RoutePacket::new_checked(value)?;

        let address_family = packet.family();
        let mut table = packet.table();
        let protocol = packet.protocol();
        let scope = packet.scope();
        let kind = packet.kind();
        let flags = packet.flags();
        let src_len = packet.src_len();
        let dst_len = packet.dst_len();

        if address_family == AddressFamily::AF_INET {
            debug_assert!(src_len == 0);
            debug_assert!(dst_len <= 32);
        } else if address_family == AddressFamily::AF_INET6 {
            debug_assert!(src_len <= 0);
            debug_assert!(dst_len <= 128);
        }

        let mut dst_cidr = None;
        let mut pref_src = None;
        let mut gateway = None;
        let mut out_ifindex = None;

        let mut payload = packet.payload();
        
        loop {
            if payload.len() < 4 {
                break;
            }

            let attr = NetlinkAttrPacket::new_checked(&payload)?;

            // let attr_payload_len = attr.payload_len();
            let attr_total_len = attr.total_len();

            let attr_kind = RouteAttrType(attr.kind());
            let attr_data = attr.payload();
            
            // println!("Route Attr: type={:15} data={:?}", format!("{:?}", attr_kind), attr_data);
            
            if attr_kind == RouteAttrType::RTA_TABLE {
                table = RouteTable(attr_data[0]);
            } else if attr_kind == RouteAttrType::RTA_DST {
                if address_family == AddressFamily::AF_INET {
                    let octets = NetworkEndian::read_u32(&attr_data);
                    let dst_addr: IpAddr = Ipv4Addr::from(octets).into();
                    dst_cidr = Some(IpCidr::new(dst_addr.into(), dst_len));
                } else if address_family == AddressFamily::AF_INET6 {
                    let octets = NetworkEndian::read_u128(&attr_data);
                    let dst_addr: IpAddr = Ipv6Addr::from(octets).into();
                    dst_cidr = Some(IpCidr::new(dst_addr.into(), dst_len));
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
            } else if attr_kind == RouteAttrType::RTA_GATEWAY {
                if address_family == AddressFamily::AF_INET {
                    let octets = NetworkEndian::read_u32(&attr_data);
                    gateway = Some(std::net::Ipv4Addr::from(octets).into());
                } else if address_family == AddressFamily::AF_INET6 {
                    let octets = NetworkEndian::read_u128(&attr_data);
                    gateway = Some(std::net::Ipv6Addr::from(octets).into())
                } else {
                    error!("Unknow Route Attr: type={:15} data={:?}", format!("{:?}", attr_kind), attr_data);
                    continue;
                }
            } else {
                trace!("Droped Route Attr: type={:15} data={:?}", format!("{:?}", attr_kind), attr_data);
            }
            
            payload = &payload[attr_total_len..];
        }

        Ok(Route{ table, protocol, scope, kind, flags, address_family, dst_cidr, pref_src, gateway, out_ifindex, })
    }
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
        
        Some(Route::try_from(pkt.payload()))
    }
}