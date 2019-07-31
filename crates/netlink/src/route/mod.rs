// Routing Family Library (libnl-route)
// 
// Adresses, links, neighbours, routing, traffic control, neighbour tables, …
use crate::packet;
use crate::socket::NetlinkSocket;

use libc::IF_NAMESIZE;

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
        let payload = ();

        header.nlmsg_type  = packet::Kind::RTM_GETLINK.into();
        header.nlmsg_flags = (packet::Flags::NLM_F_REQUEST | packet::Flags::NLM_F_DUMP).into();
        
        let mut message = packet::nlmsg::new(header, ifinfo, payload);
        message.fill_size();

        self.nl_socket.send(&message)?;

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
        let payload = ();

        header.nlmsg_type  = packet::Kind::RTM_GETADDR.into();
        header.nlmsg_flags = (packet::Flags::NLM_F_REQUEST | packet::Flags::NLM_F_DUMP).into();
        
        let mut message = packet::nlmsg::new(header, ifinfo, payload);
        message.fill_size();

        self.nl_socket.send(&message)?;

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
        let payload = ();

        header.nlmsg_type  = packet::Kind::RTM_GETROUTE.into();
        header.nlmsg_flags = (packet::Flags::NLM_F_REQUEST | packet::Flags::NLM_F_DUMP).into();
        
        let mut message = packet::nlmsg::new(header, ifinfo, payload);
        message.fill_size();

        self.nl_socket.send(&message)?;

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
        let rtmsg = packet::rtmsg::default();
        let payload = ();

        header.nlmsg_type  = packet::Kind::RTM_GETNEIGH.into();
        header.nlmsg_flags = (packet::Flags::NLM_F_REQUEST | packet::Flags::NLM_F_DUMP).into();
        
        let mut message = packet::nlmsg::new(header, rtmsg, payload);
        message.fill_size();

        self.nl_socket.send(&message)?;

        Ok(neigh::Neighbours {
            socket: &mut self.nl_socket,
            buffer: buffer,
            is_done: false,
            buffer_len: 0,
            offset: 0,
        })
    }

    pub fn add_link(&mut self, ifname: &str, mac_addr: packet::MacAddr, buffer: &mut [u8]) -> Result<(), io::Error> {
        if ifname.len() > IF_NAMESIZE - 1 {
            return Err(io::Error::new(io::ErrorKind::Other, "Interface name is too long."));
        }

        let ifname_len  = ifname.len() + 1; // ends_with `\0`
        let ifname_attr_len = packet::align(4 + ifname_len);
        let hwaddr_attr_len = packet::align(4 + std::mem::size_of::<packet::MacAddr>());

        let attrs_payload_len = ifname_attr_len + hwaddr_attr_len;
        let nl_packet_len = packet::NetlinkPacket::<&[u8]>::MIN_SIZE + packet::LinkPacket::<&[u8]>::MIN_SIZE + attrs_payload_len;

        let mut nl_packet = packet::NetlinkPacket::new_unchecked(buffer);
        nl_packet.set_len(nl_packet_len as u32);
        nl_packet.set_kind(packet::Kind::RTM_NEWLINK);
        nl_packet.set_flags(packet::Flags::NLM_F_CREATE | packet::Flags::NLM_F_EXCL | packet::Flags::NLM_F_ACK);
        nl_packet.set_seq(0);
        nl_packet.set_pid(0);

        let mut link_packet = packet::LinkPacket::new_unchecked(nl_packet.payload_mut());
        link_packet.set_family(packet::AddressFamily::AF_UNSPEC);
        link_packet.set_kind(packet::LinkKind::ARPHRD_ETHER);
        link_packet.set_ifindex(0);
        link_packet.set_flags(packet::LinkFlags::IFF_UP | packet::LinkFlags::IFF_RUNNING);
        link_packet.set_change(packet::LinkFlags::from_bits_truncate(0));
        
        // Set attrs
        let mut attrs_payload = link_packet.payload_mut();
        debug_assert_eq!(attrs_payload_len, attrs_payload.len());

        // ifname attr
        let mut ifname_attr = packet::NetlinkAttrPacket::new_unchecked(&mut attrs_payload);
        ifname_attr.set_len(ifname_attr_len as u16);
        ifname_attr.set_kind(packet::LinkAttrType::IFLA_IFNAME.into());
        let ifname_attr_payload = ifname_attr.payload_mut();
        &mut ifname_attr_payload[..ifname.len()].copy_from_slice(ifname.as_bytes());
        for x in &mut ifname_attr_payload[ifname.len()..] {
            *x = 0;
        }

        // hwaddr attr
        let mut hwaddr_attr = packet::NetlinkAttrPacket::new_unchecked(&mut attrs_payload[ifname_attr_len..]);
        hwaddr_attr.set_len(hwaddr_attr_len as u16);
        hwaddr_attr.set_kind(packet::LinkAttrType::IFLA_ADDRESS.into());
        let hwaddr_attr_payload = hwaddr_attr.payload_mut();

        let mac_addr_len = std::mem::size_of::<packet::MacAddr>();  // 6
        &mut hwaddr_attr_payload[..].copy_from_slice(&mac_addr.0);
        for x in &mut hwaddr_attr_payload[mac_addr_len..] {
            *x = 0;
        }

        let buffer = nl_packet.into_inner();

        self.nl_socket.send(&buffer[..nl_packet_len])?;

        let amt = self.nl_socket.recv(buffer)?;
        trace!("read {} bytes from netlink socket.", amt);

        // TODO: Check netlink message.
        Ok(())
    }

    pub fn remove_link(&mut self, ifindex: i32, buffer: &mut [u8]) -> Result<(), io::Error> {
        let mut header = packet::nlmsghdr::default();
        let mut ifinfo = packet::ifinfomsg::default();
        let payload = ();

        ifinfo.ifi_family = packet::AddressFamily::AF_UNSPEC.into();
        ifinfo.ifi_index  = ifindex;

        header.nlmsg_type  = packet::Kind::RTM_DELLINK.into();
        header.nlmsg_flags = packet::Flags::NLM_F_ACK.into();
        
        let mut message = packet::nlmsg::new(header, ifinfo, payload);
        message.fill_size();

        self.nl_socket.send(&message)?;

        let amt = self.nl_socket.recv(buffer)?;
        trace!("read {} bytes from netlink socket.", amt);

        // TODO: Check netlink message.
        Ok(())
    }

    pub fn remove_neighbour(&mut self) -> Result<(), io::Error> {
        // RTM_DELNEIGH
        unimplemented!()
    }

    pub fn add_route(&mut self) -> Result<(), io::Error> {
        unimplemented!()
    }

    pub fn remove_route(&mut self) -> Result<(), io::Error> {
        unimplemented!()
    }
}
