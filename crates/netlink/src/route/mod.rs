// Routing Family Library (libnl-route)
// 
// Adresses, links, neighbours, routing, traffic control, neighbour tables, …
use crate::packet;
use crate::socket::NetlinkSocket;

use libc::IF_NAMESIZE;

use std::io;
use std::net::IpAddr;
use std::convert::TryFrom;

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
        if unsafe { libc::getuid() != 0 } {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }

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
        if unsafe { libc::getuid() != 0 } {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }

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

    pub fn add_addr(&mut self) -> Result<(), io::Error> {
        // RTM_NEWADDR
        if unsafe { libc::getuid() != 0 } {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }

        unimplemented!()
    }
    
    pub fn remove_neighbour(&mut self) -> Result<(), io::Error> {
        // RTM_DELNEIGH
        if unsafe { libc::getuid() != 0 } {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }

        unimplemented!()
    }

    pub fn get_route(&mut self, dst_addr: IpAddr, prefix_len: u8, buffer: &mut [u8]) -> Result<route::Route, io::Error> {
        // ip route get 1.1.1.1
        // ip route get 1.1.1.0/24
        let address_family;
        let scope;
        let attr_dst_addr_len;

        if dst_addr.is_ipv4() {
            assert!(prefix_len <= 32);
            address_family = packet::AddressFamily::AF_INET;
            attr_dst_addr_len = packet::align(4 + 4);
        } else if dst_addr.is_ipv6() {
            assert!(prefix_len <= 128);
            address_family = packet::AddressFamily::AF_INET6;
            attr_dst_addr_len = packet::align(4 + 16);
        } else {
            unreachable!();
        }

        if dst_addr.is_unspecified() {
            // add default (0.0.0.0)
            assert_eq!(prefix_len, 0);
            scope = packet::RouteScope::RT_SCOPE_UNIVERSE;
        } else {
            scope = packet::RouteScope::RT_SCOPE_UNIVERSE;
        }
        
        let attrs_payload_len = attr_dst_addr_len;
        let nl_packet_len = packet::NetlinkPacket::<&[u8]>::MIN_SIZE + packet::RoutePacket::<&[u8]>::MIN_SIZE + attrs_payload_len;
        
        let flags = packet::Flags::NLM_F_REQUEST;

        let mut nl_packet = packet::NetlinkPacket::new_unchecked(buffer);
        nl_packet.set_len(nl_packet_len as u32);
        nl_packet.set_kind(packet::Kind::RTM_GETROUTE);
        nl_packet.set_flags(flags);
        nl_packet.set_seq(0);
        nl_packet.set_pid(0);

        let mut route_packet = packet::RoutePacket::new_unchecked(nl_packet.payload_mut());
        route_packet.set_family(address_family);
        route_packet.set_dst_len(prefix_len);
        route_packet.set_src_len(0);
        route_packet.set_tos(0);
        route_packet.set_table(packet::RouteTable::RT_TABLE_UNSPEC);
        route_packet.set_protocol(packet::RouteProtocol::RTPROT_UNSPEC);
        route_packet.set_scope(scope);
        route_packet.set_kind(packet::RouteType::RTN_UNSPEC);
        route_packet.set_flags(packet::RouteFlags::RTM_F_LOOKUP_TABLE);
        
        // Set attrs
        let mut attrs_payload = route_packet.payload_mut();
        debug_assert_eq!(attrs_payload_len, attrs_payload.len());

        // dst_addr attr
        let mut dst_addr_attr = packet::NetlinkAttrPacket::new_unchecked(&mut attrs_payload);
        dst_addr_attr.set_len(attr_dst_addr_len as u16);
        dst_addr_attr.set_kind(packet::RouteAttrType::RTA_DST.into());
        let dst_addr_attr_payload = dst_addr_attr.payload_mut();
        match dst_addr {
            IpAddr::V4(v4_addr) => {
                let dst_addr_data = v4_addr.octets();
                &mut dst_addr_attr_payload[..dst_addr_data.len()].copy_from_slice(&dst_addr_data);
                for x in &mut dst_addr_attr_payload[dst_addr_data.len()..] {
                    *x = 0;
                }
            },
            IpAddr::V6(v6_addr) => {
                let dst_addr_data = v6_addr.octets();
                &mut dst_addr_attr_payload[..dst_addr_data.len()].copy_from_slice(&dst_addr_data);
                for x in &mut dst_addr_attr_payload[dst_addr_data.len()..] {
                    *x = 0;
                }
            },
        };

        let buffer = nl_packet.into_inner();

        self.nl_socket.send(&buffer[..nl_packet_len])?;
        for x in &mut buffer[..] {
            *x = 0;
        }

        let amt = self.nl_socket.recv(buffer)?;
        debug!("read {} bytes from netlink socket.", amt);

        let nl_pkt = packet::NetlinkPacket::new_checked(&buffer[..amt])?;

        let rt = route::Route::try_from(nl_pkt.payload())?;

        Ok(rt)
    }

    pub fn add_route(&mut self,
                     dst_addr: IpAddr,
                     prefix_len: u8,
                     gateway: Option<IpAddr>,
                     ifindex: Option<u32>,
                     buffer: &mut [u8]) -> Result<(), io::Error> {
        if unsafe { libc::getuid() != 0 } {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }

        let address_family;
        let scope;
        let attr_dst_addr_len;
        let attr_ifindex_len;
        let attr_gateway_len;

        match (ifindex, gateway) {
            (Some(_), Some(_)) => {
                // sudo ip route add 1.1.1.1    via 192.168.1.100 dev eth0
                // sudo ip route add 1.1.1.0/24 via 192.168.1.100 dev eth0
            },
            (Some(_), None) => {
                // sudo ip route add 1.1.1.1    dev enp0s3
                // sudo ip route add 1.1.1.0/24 dev enp0s3
            },
            (None, Some(_)) => {
                // sudo ip route add 1.1.1.1    via 192.168.1.1
                // sudo ip route add 1.1.1.0/24 via 192.168.1.1
            },
            (None, None) => {
                return Err(io::Error::new(io::ErrorKind::Other, "gateway or ifindex provide at least one."));
            },
        }

        if ifindex.is_some() {
            attr_ifindex_len = packet::align(4 + 4);
        } else {
            attr_ifindex_len = 0;
        }

        match gateway {
            Some(gateway_addr) => {
                if gateway_addr.is_ipv4() {
                    attr_gateway_len = packet::align(4 + 4);
                } else if gateway_addr.is_ipv6() {
                    attr_gateway_len = packet::align(4 + 16);
                } else {
                     unreachable!();
                }
            },
            None => {
                attr_gateway_len = 0;
            }
        }

        if dst_addr.is_ipv4() {
            assert!(prefix_len <= 32);
            address_family = packet::AddressFamily::AF_INET;
            attr_dst_addr_len = packet::align(4 + 4);
        } else if dst_addr.is_ipv6() {
            assert!(prefix_len <= 128);
            address_family = packet::AddressFamily::AF_INET6;
            attr_dst_addr_len = packet::align(4 + 16);
        } else {
            unreachable!();
        }

        if dst_addr.is_unspecified() {
            // add default (0.0.0.0)
            assert_eq!(prefix_len, 0);
            scope = packet::RouteScope::RT_SCOPE_UNIVERSE;
        } else {
            scope = packet::RouteScope::RT_SCOPE_LINK;
            // scope = packet::RouteScope::RT_SCOPE_NOWHERE;
            // scope = packet::RouteScope::RT_SCOPE_UNIVERSE;
        }

        let attrs_payload_len = attr_dst_addr_len + attr_ifindex_len + attr_gateway_len;
        let nl_packet_len = packet::NetlinkPacket::<&[u8]>::MIN_SIZE + packet::RoutePacket::<&[u8]>::MIN_SIZE + attrs_payload_len;

        let flags = packet::Flags::NLM_F_CREATE | packet::Flags::NLM_F_EXCL | packet::Flags::NLM_F_REQUEST
            | packet::Flags::NLM_F_ACK;

        let mut nl_packet = packet::NetlinkPacket::new_unchecked(buffer);
        nl_packet.set_len(nl_packet_len as u32);
        nl_packet.set_kind(packet::Kind::RTM_NEWROUTE);
        nl_packet.set_flags(flags);
        nl_packet.set_seq(0);
        nl_packet.set_pid(0);

        let mut route_packet = packet::RoutePacket::new_unchecked(nl_packet.payload_mut());
        route_packet.set_family(address_family);
        route_packet.set_dst_len(prefix_len);
        route_packet.set_src_len(0);
        route_packet.set_tos(0);
        route_packet.set_table(packet::RouteTable::RT_TABLE_MAIN);
        route_packet.set_protocol(packet::RouteProtocol::RTPROT_BOOT);
        route_packet.set_scope(scope);
        route_packet.set_kind(packet::RouteType::RTN_UNICAST);
        route_packet.set_flags(packet::RouteFlags::from_bits_truncate(0));
        
        // Set attrs
        let mut attrs_payload = route_packet.payload_mut();
        debug_assert_eq!(attrs_payload_len, attrs_payload.len());

        // dst_addr attr
        let mut dst_addr_attr = packet::NetlinkAttrPacket::new_unchecked(&mut attrs_payload);
        dst_addr_attr.set_len(attr_dst_addr_len as u16);
        dst_addr_attr.set_kind(packet::RouteAttrType::RTA_DST.into());
        let dst_addr_attr_payload = dst_addr_attr.payload_mut();
        match dst_addr {
            IpAddr::V4(v4_addr) => {
                let dst_addr_data = v4_addr.octets();
                &mut dst_addr_attr_payload[..dst_addr_data.len()].copy_from_slice(&dst_addr_data);
                for x in &mut dst_addr_attr_payload[dst_addr_data.len()..] {
                    *x = 0;
                }
            },
            IpAddr::V6(v6_addr) => {
                let dst_addr_data = v6_addr.octets();
                &mut dst_addr_attr_payload[..dst_addr_data.len()].copy_from_slice(&dst_addr_data);
                for x in &mut dst_addr_attr_payload[dst_addr_data.len()..] {
                    *x = 0;
                }
            },
        };
        
        // RTA_VIA
        // gateway_addr attr
        if gateway.is_some() {
            let mut gateway_addr_attr = packet::NetlinkAttrPacket::new_unchecked(&mut attrs_payload[attr_dst_addr_len..]);
            gateway_addr_attr.set_len(attr_gateway_len as u16);
            gateway_addr_attr.set_kind(packet::RouteAttrType::RTA_GATEWAY.into());
            let gateway_addr_attr_payload = gateway_addr_attr.payload_mut();
            match gateway.unwrap() {
                IpAddr::V4(v4_addr) => {
                    let gateway_addr_data = v4_addr.octets();
                    &mut gateway_addr_attr_payload[..gateway_addr_data.len()].copy_from_slice(&gateway_addr_data);
                    for x in &mut gateway_addr_attr_payload[gateway_addr_data.len()..] {
                        *x = 0;
                    }
                },
                IpAddr::V6(v6_addr) => {
                    let gateway_addr_data = v6_addr.octets();
                    &mut gateway_addr_attr_payload[..gateway_addr_data.len()].copy_from_slice(&gateway_addr_data);
                    for x in &mut gateway_addr_attr_payload[gateway_addr_data.len()..] {
                        *x = 0;
                    }
                },
            };
        }

        // out_ifindex attr
        if ifindex.is_some() {
            let offset = if gateway.is_some() { attr_dst_addr_len + attr_gateway_len } else { attr_dst_addr_len };
            let mut out_ifindex_attr = packet::NetlinkAttrPacket::new_unchecked(&mut attrs_payload[offset..]);
            
            out_ifindex_attr.set_len(attr_ifindex_len as u16);
            out_ifindex_attr.set_kind(packet::RouteAttrType::RTA_OIF.into());
            let out_ifindex_attr_payload = out_ifindex_attr.payload_mut();
            let ifindex = ifindex.unwrap();
            &mut out_ifindex_attr_payload[..4].copy_from_slice(&ifindex.to_ne_bytes());
            for x in &mut out_ifindex_attr_payload[4..] {
                *x = 0;
            }
        }

        let buffer = nl_packet.into_inner();

        {
            let pkt = packet::NetlinkPacket::new_unchecked(&buffer);
            trace!("try send netlink message:\n{}", pkt);
            let rt_pkt = packet::RoutePacket::new_unchecked(pkt.payload());
            trace!("{}", rt_pkt);
        }
        for x in &mut buffer[nl_packet_len..nl_packet_len] {
            *x = 0;
        }

        self.nl_socket.send(&buffer[..nl_packet_len])?;
        for x in &mut buffer[..] {
            *x = 0;
        }

        let amt = self.nl_socket.recv(buffer)?;
        debug!("read {} bytes from netlink socket.", amt);

        let pkt = packet::NetlinkPacket::new_checked(&buffer[..amt])?;
        trace!("{}", pkt);
        let err_pkt = packet::NetlinkErrorPacket::new_unchecked(&pkt.payload()[..]);
        if err_pkt.errorno() != 0 {
            // TODO: 检查详细的错误类型？
            //       比如要删除的地址并不存在等。
            error!("{}", err_pkt);
            return Err(err_pkt.err());
        }

        Ok(())
    }
    
    pub fn remove_route(&mut self, dst_addr: IpAddr, prefix_len: u8, buffer: &mut [u8]) -> Result<(), io::Error> {
        // sudo ip route del 1.1.1.1
        // sudo ip route del 1.1.1.1/24
        if unsafe { libc::getuid() != 0 } {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }

        let address_family;
        let scope;
        let attr_dst_addr_len;
        
        if dst_addr.is_ipv4() {
            assert!(prefix_len <= 32);
            address_family = packet::AddressFamily::AF_INET;
            attr_dst_addr_len = packet::align(4 + 4);
        } else if dst_addr.is_ipv6() {
            assert!(prefix_len <= 128);
            address_family = packet::AddressFamily::AF_INET6;
            attr_dst_addr_len = packet::align(4 + 16);
        } else {
            unreachable!();
        }

        if dst_addr.is_unspecified() {
            // add default (0.0.0.0)
            assert_eq!(prefix_len, 0);
            scope = packet::RouteScope::RT_SCOPE_UNIVERSE;
        } else {
            // scope = packet::RouteScope::RT_SCOPE_LINK;
            scope = packet::RouteScope::RT_SCOPE_NOWHERE;
        }

        let attrs_payload_len = attr_dst_addr_len;
        let nl_packet_len = packet::NetlinkPacket::<&[u8]>::MIN_SIZE + packet::RoutePacket::<&[u8]>::MIN_SIZE + attrs_payload_len;

        let mut nl_packet = packet::NetlinkPacket::new_unchecked(buffer);
        nl_packet.set_len(nl_packet_len as u32);
        nl_packet.set_kind(packet::Kind::RTM_DELROUTE);
        nl_packet.set_flags(packet::Flags::NLM_F_REQUEST | packet::Flags::NLM_F_ACK);
        nl_packet.set_seq(0);
        nl_packet.set_pid(0);

        let mut route_packet = packet::RoutePacket::new_unchecked(nl_packet.payload_mut());
        route_packet.set_family(address_family);
        route_packet.set_dst_len(prefix_len);
        route_packet.set_src_len(0);
        route_packet.set_tos(0);
        route_packet.set_table(packet::RouteTable::RT_TABLE_MAIN);
        route_packet.set_protocol(packet::RouteProtocol::RTPROT_UNSPEC);
        route_packet.set_scope(scope);
        route_packet.set_kind(packet::RouteType::RTN_UNSPEC);
        route_packet.set_flags(packet::RouteFlags::from_bits_truncate(0));
        
        // Set attrs
        let mut attrs_payload = route_packet.payload_mut();
        debug_assert_eq!(attrs_payload_len, attrs_payload.len());

        // dst_addr attr
        let mut dst_addr_attr = packet::NetlinkAttrPacket::new_unchecked(&mut attrs_payload);
        dst_addr_attr.set_len(attr_dst_addr_len as u16);
        dst_addr_attr.set_kind(packet::RouteAttrType::RTA_DST.into());
        let dst_addr_attr_payload = dst_addr_attr.payload_mut();
        match dst_addr {
            IpAddr::V4(v4_addr) => {
                let dst_addr_data = v4_addr.octets();
                &mut dst_addr_attr_payload[..dst_addr_data.len()].copy_from_slice(&dst_addr_data);
                for x in &mut dst_addr_attr_payload[dst_addr_data.len()..] {
                    *x = 0;
                }
            },
            IpAddr::V6(v6_addr) => {
                let dst_addr_data = v6_addr.octets();
                &mut dst_addr_attr_payload[..dst_addr_data.len()].copy_from_slice(&dst_addr_data);
                for x in &mut dst_addr_attr_payload[dst_addr_data.len()..] {
                    *x = 0;
                }
            },
        };

        let buffer = nl_packet.into_inner();

        {
            let pkt = packet::NetlinkPacket::new_unchecked(&buffer);
            trace!("try send netlink message:\n{}", pkt);
            let rt_pkt = packet::RoutePacket::new_unchecked(pkt.payload());
            trace!("{}", rt_pkt);
        }
        for x in &mut buffer[nl_packet_len..nl_packet_len] {
            *x = 0;
        }

        self.nl_socket.send(&buffer[..nl_packet_len])?;
        for x in &mut buffer[..] {
            *x = 0;
        }

        let amt = self.nl_socket.recv(buffer)?;
        trace!("read {} bytes from netlink socket.", amt);

        let pkt = packet::NetlinkPacket::new_checked(&buffer[..amt])?;
        trace!("{}", pkt);
        let err_pkt = packet::NetlinkErrorPacket::new_unchecked(&pkt.payload()[..]);
        if err_pkt.errorno() != 0 {
            // TODO: 检查详细的错误类型？
            //       比如要删除的地址并不存在等。
            error!("{}", err_pkt);
            return Err(err_pkt.err());
        }
        
        Ok(())
    }
}
