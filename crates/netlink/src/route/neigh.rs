use crate::sys;
use crate::packet::Kind;
use crate::packet::MacAddr;
use crate::packet::NetlinkPacket;
use crate::packet::NetlinkErrorPacket;
use crate::packet::NeighbourPacket;
use crate::packet::RoutePacket;


use std::io;

// Routing/neighbour discovery messages.

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Neighbour {
    pub ifindex: u32,
    pub dst_addr: std::net::IpAddr,
    pub hw_addr: MacAddr,
}

pub struct Neighbours<'a, 'b> {
    pub(crate) socket: &'a mut sys::NetlinkSocket,
    pub(crate) buffer: &'b mut [u8],
    pub(crate) is_done: bool,
    pub(crate) buffer_len: usize,
    pub(crate) offset: usize,
}

impl<'a, 'b> Neighbours<'a, 'b> {
    fn next_packet(&mut self) -> Result<Option<NetlinkPacket<&[u8]>>, io::Error> {
        if self.offset >= self.buffer_len {
            let amt = self.socket.recv(&mut self.buffer, 0)?;
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
            Kind::Noop     => Ok(None),
            Kind::Error    => Err(NetlinkErrorPacket::new_checked(pkt.payload())?.err()),
            Kind::Done     => {
                self.is_done = true;
                Ok(None)
            },
            Kind::Overrun  => Err(io::Error::new(io::ErrorKind::InvalidData, "Overrun")),
            Kind::NewNeigh => Ok(Some(pkt)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, format!("Netlink Message Type is not `{:?}`", Kind::NewNeigh))),
        }
    }
}

impl<'a, 'b> Iterator for Neighbours<'a, 'b> {
    type Item = Result<Neighbour, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done {
            return None;
        }

        let pkt = match self.next_packet() {
            Ok(Some(pkt)) => pkt,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };

        let packet = match NeighbourPacket::new_checked(pkt.payload()) {
            Ok(pkt) => pkt,
            Err(e) => return Some(Err(e)),
        };

        let ifindex = packet.ifindex() as u32;
        let dst_addr = packet.dst_addr();
        let link_addr = packet.link_addr();

        Some(Ok(Neighbour { ifindex, dst_addr, hw_addr: link_addr }))
    }
}
