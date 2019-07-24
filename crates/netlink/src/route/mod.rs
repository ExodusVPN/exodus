// Routing Family Library (libnl-route)
// 
// Adresses, links, neighbours, routing, traffic control, neighbour tables, …

pub mod link;
pub mod neigh;
pub mod route;

use crate::sys;

use std::io;


// Routing/neighbour discovery messages.
pub struct RouteController {
    nl_socket: sys::NetlinkSocket,
}

impl RouteController {
    pub fn new() -> Result<Self, io::Error> {
        let mut nl_socket = sys::NetlinkSocket::new(sys::NETLINK_ROUTE as i32)?;
        
        let pid    = 0;
        let groups = 0;
        nl_socket.bind(pid, groups)?;

        Ok(Self { nl_socket })
    }

    pub fn links<'a, 'b>(&'a mut self, buffer: &'b mut [u8]) -> Result<link::Links<'a, 'b>, io::Error> {
        unimplemented!()
    }

    pub fn addrs<'a, 'b>(&'a mut self, buffer: &'b mut [u8]) -> Result<link::Links<'a, 'b>, io::Error> {
        unimplemented!()
    }

    pub fn routes<'a, 'b>(&'a mut self, buffer: &'b mut [u8]) -> Result<route::Routes<'a, 'b>, io::Error> {
        unimplemented!()
    }

    pub fn neighbours<'a, 'b>(&'a mut self, buffer: &'b mut [u8]) -> Result<neigh::Neighbours<'a, 'b>, io::Error> {
        let mut header = sys::nlmsghdr::default();
        let body = sys::rtmsg::default();

        header.nlmsg_type  = sys::RTM_GETNEIGH;
        header.nlmsg_flags = sys::NLM_F_REQUEST | sys::NLM_F_DUMP;
        
        let mut message = sys::Request::new(header, body);
        message.fill_size();

        self.nl_socket.send2(&message)?;

        Ok(neigh::Neighbours {
            socket: &mut self.nl_socket,
            buffer: buffer,
            packet_ptr: None,
            packet_len: 0,
            is_done: false,
            ifindex: 0,
        })
    }

    pub fn add_neighbour(&mut self) -> Result<(), io::Error> {
        // RTM_NEWNEIGH
        unimplemented!()
    }

    pub fn remove_neighbour(&mut self) -> Result<(), io::Error> {
        // RTM_DELNEIGH
        unimplemented!()
    }
}








