use crate::sys;
use crate::packet::MacAddr;
use crate::packet::RoutePacket;


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

// const RT_MSG_LEN: usize = std::mem::size_of::<sys::rtmsg>();
// const RT_ATTR_LEN: usize = std::mem::size_of::<sys::rtattr>();
// const NL_ATTR_LEN: usize = std::mem::size_of::<sys::nlattr>();


impl<'a, 'b> Routes<'a, 'b> {
    fn next_packet(&mut self) -> Result<(), io::Error> {
        let data = unsafe { std::mem::transmute::<&mut [u8], &'b mut [u8]>(&mut self.buffer) };
        let iter = self.socket.recvmsg(data)?;

        for x in iter {
            let nl_packet = x?;
            let packet = RoutePacket::new_checked(nl_packet.payload())?;
            let attrs = packet.payload();
            println!("{}", packet);
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

        return None;
    }
}