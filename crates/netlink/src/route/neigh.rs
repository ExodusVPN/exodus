use crate::sys;
use crate::packet::neighbour::MacAddr;
use crate::packet::neighbour::NeighbourPacket;


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
    pub(crate) packets: Option<sys::NetlinkPacketIter<'b>>,
    pub(crate) is_done: bool,
}

impl<'a, 'b> Neighbours<'a, 'b> {
    fn next_packet(&mut self) -> Result<(), io::Error> {
        let data = unsafe { std::mem::transmute::<&mut [u8], &'b mut [u8]>(&mut self.buffer) };
        let iter = self.socket.recvmsg(data)?;
        self.packets = Some(iter);
        
        Ok(())
    }
}

impl<'a, 'b> Iterator for Neighbours<'a, 'b> {
    type Item = Result<Neighbour, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done {
            return None;
        }

        if self.packets.is_none() {
            if let Err(e) = self.next_packet() {
                return Some(Err(e));
            }
        }

        if self.packets.is_none() {
            self.is_done = true;
            return None;
        }

        let mut packets = self.packets.as_mut().unwrap();
        
        let pkt = match packets.next() {
            Some(Ok(pkt)) => pkt,
            Some(Err(e)) => return Some(Err(e)),
            None => return None,
        };

        let kind = pkt.kind();
        if kind.is_done() {
            self.is_done = true;
            return None;
        }

        let kind_num: u16 = kind.into();
        if kind_num != sys::RTM_NEWNEIGH {
            return None;
        }

        let neigh_packet = match NeighbourPacket::new_checked(pkt.payload()) {
            Ok(pkt) => pkt,
            Err(e) => return Some(Err(e)),
        };

        let ifindex = neigh_packet.ifindex() as u32;
        let dst_addr = neigh_packet.dst_addr();
        let link_addr = neigh_packet.link_addr();

        Some(Ok(Neighbour { ifindex, dst_addr, hw_addr: link_addr }))
    }
}
