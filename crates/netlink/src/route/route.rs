use crate::sys;
use crate::packet::neighbour::MacAddr;
use crate::packet::route::RoutePacket;


use std::io;


#[derive(Debug, Clone, Copy)]
pub struct Route {

}

pub struct Routes<'a, 'b> {
    pub(crate) socket: &'a mut sys::NetlinkSocket,
    pub(crate) buffer: &'b mut [u8],
    pub(crate) packets: Option<sys::NetlinkPacketIter<'b>>,
    pub(crate) is_done: bool,
}

const RT_MSG_LEN: usize = std::mem::size_of::<sys::rtmsg>();
const RT_ATTR_LEN: usize = std::mem::size_of::<sys::rtattr>();
const NL_ATTR_LEN: usize = std::mem::size_of::<sys::nlattr>();


impl<'a, 'b> Routes<'a, 'b> {
    fn next_packet(&mut self) -> Result<(), io::Error> {
        let data = unsafe { std::mem::transmute::<&mut [u8], &'b mut [u8]>(&mut self.buffer) };
        let iter = self.socket.recvmsg(data)?;

        for x in iter {
            let nl_packet = x?;
            let packet = RoutePacket::new_checked(nl_packet.payload())?;
            let attrs = packet.payload();
            println!("src len: {:2?} dst len: {:2?}  attrs: {:?}",
                packet.src_len(),
                packet.dst_len(),
                attrs);
        }
        // self.packets = Some(iter);
        
        Ok(())
    }
}

impl<'a, 'b> Iterator for Routes<'a, 'b> {
    type Item = Result<Route, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        // sys::RTM_NEWROUTE
        // unimplemented!()
        self.next_packet();

        // Payload
        // [8, 0, 15, 0, 254, 0, 0, 0, 8, 0, 6, 0, 100,   0,   0,   0, 8, 0, 5, 0, 192, 168, 199,   1, 8, 0, 4, 0, 2, 0, 0, 0]
        // [8, 0, 15, 0, 254, 0, 0, 0, 8, 0, 1, 0, 169, 254,   0,   0, 8, 0, 6, 0, 232,   3,   0,   0, 8, 0, 4, 0, 2, 0, 0, 0]
        // [8, 0, 15, 0, 254, 0, 0, 0, 8, 0, 1, 0, 172,  17,   0,   0, 8, 0, 7, 0, 172,  17,   0,   1, 8, 0, 4, 0, 3, 0, 0, 0]
        // [8, 0, 15, 0, 254, 0, 0, 0, 8, 0, 1, 0, 192, 168, 199,   0, 8, 0, 6, 0, 100,   0,   0,   0, 8, 0, 7, 0, 192, 168, 199, 232, 8, 0, 4, 0, 2, 0, 0, 0]
        // [8, 0, 15, 0, 255, 0, 0, 0, 8, 0, 1, 0, 127,   0,   0,   0, 8, 0, 7, 0, 127,   0,   0,   1, 8, 0, 4, 0, 1, 0, 0, 0]
        // [8, 0, 15, 0, 255, 0, 0, 0, 8, 0, 1, 0, 127,   0,   0,   0, 8, 0, 7, 0, 127,   0,   0,   1, 8, 0, 4, 0, 1, 0, 0, 0]
        // [8, 0, 15, 0, 255, 0, 0, 0, 8, 0, 1, 0, 127,   0,   0,   1, 8, 0, 7, 0, 127,   0,   0,   1, 8, 0, 4, 0, 1, 0, 0, 0]
        // [8, 0, 15, 0, 255, 0, 0, 0, 8, 0, 1, 0, 127, 255, 255, 255, 8, 0, 7, 0, 127,   0,   0,   1, 8, 0, 4, 0, 1, 0, 0, 0]
        // [8, 0, 15, 0, 255, 0, 0, 0, 8, 0, 1, 0, 172,  17,   0,   0, 8, 0, 7, 0, 172,  17,   0,   1, 8, 0, 4, 0, 3, 0, 0, 0]
        // [8, 0, 15, 0, 255, 0, 0, 0, 8, 0, 1, 0, 172,  17,   0,   1, 8, 0, 7, 0, 172,  17,   0,   1, 8, 0, 4, 0, 3, 0, 0, 0]
        // [8, 0, 15, 0, 255, 0, 0, 0, 8, 0, 1, 0, 172,  17, 255, 255, 8, 0, 7, 0, 172,  17,   0,   1, 8, 0, 4, 0, 3, 0, 0, 0]
        // [8, 0, 15, 0, 255, 0, 0, 0, 8, 0, 1, 0, 192, 168, 199,   0, 8, 0, 7, 0, 192, 168, 199, 232, 8, 0, 4, 0, 2, 0, 0, 0]
        // [8, 0, 15, 0, 255, 0, 0, 0, 8, 0, 1, 0, 192, 168, 199, 232, 8, 0, 7, 0, 192, 168, 199, 232, 8, 0, 4, 0, 2, 0, 0, 0]
        // [8, 0, 15, 0, 255, 0, 0, 0, 8, 0, 1, 0, 192, 168, 199, 255, 8, 0, 7, 0, 192, 168, 199, 232, 8, 0, 4, 0, 2, 0, 0, 0]
        return None;
    }
}