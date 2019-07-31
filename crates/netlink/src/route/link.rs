use crate::socket::NetlinkSocket;
use crate::packet::Kind;
use crate::packet::MacAddr;
use crate::packet::NetlinkPacket;
use crate::packet::NetlinkErrorPacket;
use crate::packet::NetlinkAttrPacket;
use crate::packet::LinkPacket;
use crate::packet::LinkAttrType;
use crate::packet::LinkFlags;
use crate::packet::LinkKind;
use crate::packet::LinkMode;
use crate::packet::LinkOperState;
use crate::packet::LinkName;

use libc::IF_NAMESIZE;
use byteorder::{ByteOrder, NativeEndian};

use std::io;


#[derive(Debug, Clone, Copy)]
pub struct Link {
    pub ifindex: u32,
    pub kind: LinkKind,
    pub flags: LinkFlags,
    // Attrs
    pub ifname: Option<LinkName>,
    pub mtu: Option<u32>,
    pub mode: Option<LinkMode>,
    pub oper_state: Option<LinkOperState>,
    pub addr: Option<MacAddr>,
    pub broadcast: Option<MacAddr>,
}

pub struct Links<'a, 'b> {
    pub(crate) socket: &'a mut NetlinkSocket,
    pub(crate) buffer: &'b mut [u8],
    pub(crate) is_done: bool,
    pub(crate) buffer_len: usize,
    pub(crate) offset: usize,
}

impl<'a, 'b> Links<'a, 'b> {
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
            Kind::RTM_NEWLINK => Ok(Some(pkt)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, format!("Netlink Message Type is not `{:?}`", Kind::RTM_NEWLINK))),
        }
    }
}

impl<'a, 'b> Iterator for Links<'a, 'b> {
    type Item = Result<Link, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done {
            return None;
        }

        let pkt = match self.next_packet() {
            Ok(Some(pkt)) => pkt,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        
        let packet = match LinkPacket::new_checked(pkt.payload()) {
            Ok(pkt) => pkt,
            Err(e) => return Some(Err(e)),
        };
        
        // let address_family = packet.family();
        let kind = packet.kind();
        let ifindex = packet.ifindex() as u32;
        let flags = packet.flags();

        let mut ifname = None;
        let mut mtu = None;
        let mut mode = None;
        let mut oper_state = None;
        let mut addr = None;
        let mut broadcast = None;

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

            let attr_kind = LinkAttrType(attr.kind());
            let attr_data = attr.payload();
            
            if attr_kind == LinkAttrType::IFLA_IFNAME {
                let mut _name = [0u8; IF_NAMESIZE];
                (&mut _name[..attr_data.len()]).copy_from_slice(&attr_data);
                ifname = Some(LinkName::new(_name, attr_data.len()));
            } else if attr_kind == LinkAttrType::IFLA_OPERSTATE {
                oper_state = Some(LinkOperState(NativeEndian::read_u32(&attr_data)));
            } else if attr_kind == LinkAttrType::IFLA_LINKMODE {
                mode = Some(LinkMode(NativeEndian::read_u32(&attr_data)));
            } else if attr_kind == LinkAttrType::IFLA_MTU {
                mtu = Some(NativeEndian::read_u32(&attr_data));
            } else if attr_kind == LinkAttrType::IFLA_ADDRESS {
                addr = Some(MacAddr([
                                attr_data[0], attr_data[1], attr_data[2],
                                attr_data[3], attr_data[4], attr_data[5]]));
            } else if attr_kind == LinkAttrType::IFLA_BROADCAST {
                broadcast = Some(MacAddr([
                                attr_data[0], attr_data[1], attr_data[2],
                                attr_data[3], attr_data[4], attr_data[5]]));
            } else {
                trace!("Droped Link Attr: type={:15} data={:?}", format!("{:?}", attr_kind), attr_data);
            }
            
            payload = &payload[attr_total_len..];
        }

        Some(Ok(Link{ ifindex, kind, flags, ifname, mtu, mode, oper_state, addr, broadcast, }))
    }
}