// Routing Family Library (libnl-route)
// 
// Adresses, links, neighbours, routing, traffic control, neighbour tables, …
use crate::packet;
use crate::socket::NetlinkSocket;

use std::io;


pub mod link;
pub mod neigh;
pub mod route;
pub mod addr;

// Routing/neighbour discovery messages.
pub struct RouteController {
    nl_socket: NetlinkSocket,
}

impl RouteController {
    pub fn new() -> Result<Self, io::Error> {
        let mut nl_socket = NetlinkSocket::new(packet::Protocol::NETLINK_ROUTE.into())?;
        
        let pid    = 0;
        let groups = 0;
        nl_socket.bind(pid, groups)?;

        Ok(Self { nl_socket })
    }

    pub fn links<'a, 'b>(&'a mut self, buffer: &'b mut [u8]) -> Result<link::Links<'a, 'b>, io::Error> {
        let mut header = packet::nlmsghdr::default();
        let ifinfo = packet::ifinfomsg::default();

        header.nlmsg_type  = packet::Kind::RTM_GETLINK.into();
        header.nlmsg_flags = (packet::Flags::NLM_F_REQUEST | packet::Flags::NLM_F_DUMP).into();
        
        let mut message = packet::nlmsg::new(header, ifinfo);
        message.fill_size();

        self.nl_socket.send2(&message)?;

        Ok(link::Links {
            socket: &mut self.nl_socket,
            buffer: buffer,
            is_done: false,
            buffer_len: 0,
            offset: 0,
        })
    }

    pub fn addrs<'a, 'b>(&'a mut self, buffer: &'b mut [u8]) -> Result<addr::Addrs<'a, 'b>, io::Error> {
        let mut header = packet::nlmsghdr::default();
        let ifinfo = packet::ifinfomsg::default();

        header.nlmsg_type  = packet::Kind::RTM_GETADDR.into();
        header.nlmsg_flags = (packet::Flags::NLM_F_REQUEST | packet::Flags::NLM_F_DUMP).into();
        
        let mut message = packet::nlmsg::new(header, ifinfo);
        message.fill_size();

        self.nl_socket.send2(&message)?;

        Ok(addr::Addrs {
            socket: &mut self.nl_socket,
            buffer: buffer,
            is_done: false,
            buffer_len: 0,
            offset: 0,
        })
    }

    pub fn routes<'a, 'b>(&'a mut self, buffer: &'b mut [u8]) -> Result<route::Routes<'a, 'b>, io::Error> {
        let mut header = packet::nlmsghdr::default();
        let ifinfo = packet::ifinfomsg::default();

        header.nlmsg_type  = packet::Kind::RTM_GETROUTE.into();
        header.nlmsg_flags = (packet::Flags::NLM_F_REQUEST | packet::Flags::NLM_F_DUMP).into();
        
        let mut message = packet::nlmsg::new(header, ifinfo);
        message.fill_size();

        self.nl_socket.send2(&message)?;

        Ok(route::Routes {
            socket: &mut self.nl_socket,
            buffer: buffer,
            is_done: false,
            buffer_len: 0,
            offset: 0,
        })
    }

    pub fn neighbours<'a, 'b>(&'a mut self, buffer: &'b mut [u8]) -> Result<neigh::Neighbours<'a, 'b>, io::Error> {
        let mut header = packet::nlmsghdr::default();
        let body = packet::rtmsg::default();

        header.nlmsg_type  = packet::Kind::RTM_GETNEIGH.into();
        header.nlmsg_flags = (packet::Flags::NLM_F_REQUEST | packet::Flags::NLM_F_DUMP).into();
        
        let mut message = packet::nlmsg::new(header, body);
        message.fill_size();

        self.nl_socket.send2(&message)?;

        Ok(neigh::Neighbours {
            socket: &mut self.nl_socket,
            buffer: buffer,
            is_done: false,
            buffer_len: 0,
            offset: 0,
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








