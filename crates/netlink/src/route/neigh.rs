use crate::sys;

use std::io::{self};

// Routing/neighbour discovery messages.

// neighbour states
// NeighbourState::from_bits_truncate(val)
bitflags! {
    pub struct NeighbourState: u16 {
        const INCOMPLETE =  0x1; // Still attempting to resolve.
        const REACHABLE  =  0x2; // A confirmed working cache entry.
        const STALE      =  0x4; // an expired cache entry.
        const DELAY      =  0x8; // Neighbor no longer reachable.
                                 // Traffic sent, waiting for confirmation.
        const PROBE      = 0x10; // A cache entry that is currently
                                 // being re-solicited.
        const FAILED     = 0x20; // An invalid cache entry.
        // Dummy states
        const NOARP      = 0x40; // A device that does not do neighbour discovery
        const PERMANENT  = 0x80; // Permanently set entries
    }
}

// neighbour flags
bitflags! {
    pub struct NeighbourFlags: u8 {
        const USE         =  0x1;
        const SELF        =  0x2;
        const MASTER      =  0x4;
        const PROXY       =  0x8;
        const EXT_LEARNED = 0x10;
        const ROUTER      = 0x80;
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum NeighbourKind {
    UNSPEC    = 0,
    DST       = 1,
    LLADDR    = 2,
    CACHEINFO = 3,
}

#[allow(non_camel_case_types, non_upper_case_globals)]
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum NeighbourAttributes {
    UNSPEC       = 0,
    DST          = 1,
    LLADDR       = 2,
    CACHEINFO    = 3,
    PROBES       = 4,
    VLAN         = 5,
    PORT         = 6,
    VNI          = 7,
    IFINDEX      = 8,
    MASTER       = 9,
    LINK_NETNSID = 10,
}

impl Default for NeighbourState {
    fn default() -> Self {
        NeighbourState::INCOMPLETE
    }
}

impl Default for NeighbourFlags {
    fn default() -> Self {
        NeighbourFlags::USE
    }
}

impl Default for NeighbourKind {
    fn default() -> Self {
        NeighbourKind::UNSPEC
    }
}

impl Default for NeighbourAttributes {
    fn default() -> Self {
        NeighbourAttributes::UNSPEC
    }
}

// prefixmsg
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Neighbour2 {
    pub family: u8,
    pub reserved1: u8,
    pub reserved2: u16,
    pub ifindex: i32,
    pub state: NeighbourState,  // u16
    pub flags: NeighbourFlags,  // u8
    pub kind : NeighbourKind,   // u8
}

#[derive(Clone, Copy)]
pub enum Address {
    IPv4(std::net::Ipv4Addr),
    IPv6(std::net::Ipv6Addr),
    Link([u8; 6]),
}


#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Neighbour {
    pub ifindex: u32,
    pub dst_addr: Address,
    pub hw_addr: Address,
}

pub struct Neighbours<'a, 'b> {
    pub(crate) socket: &'a mut sys::NetlinkSocket,
    pub(crate) buffer: &'b mut [u8],
    pub(crate) packet_ptr: Option<*const u8>,
    pub(crate) packet_len: usize,
    pub(crate) is_done: bool,
    pub(crate) ifindex: u32,
}

impl<'a, 'b> Neighbours<'a, 'b> {
    pub fn next_packet(&mut self) -> Result<(), io::Error> {
        let payload = self.socket.recvmsg(&mut self.buffer, sys::RTM_NEWNEIGH)?;
        let payload_ptr = payload.as_ptr();

        self.packet_len = payload.len();

        if self.packet_len > 0 {
            let prefix_msg = unsafe { std::mem::transmute::<*const u8, &sys::prefixmsg>(payload_ptr) };
            self.ifindex = prefix_msg.prefix_ifindex as u32;
            let payload_ptr = unsafe { payload_ptr.add(std::mem::size_of::<sys::prefixmsg>()) };
            self.packet_ptr = Some(payload_ptr);
        }
        
        Ok(())
    }

    fn read_rtattr(&mut self, ptr: *const u8) -> Option<(*const u8, Address)> {
        let rtnl_attr = unsafe { std::mem::transmute::<*const u8, &sys::rtattr>(ptr) };
        let ptr = unsafe { ptr.add(std::mem::size_of::<sys::rtattr>()) };

        if rtnl_attr.rta_len == 8 {
            // IPV4 Address
            let octets = unsafe { std::mem::transmute::<*const u8, &[u8; 4]>(ptr) };
            let addr = std::net::Ipv4Addr::from(*octets);
            let ptr = unsafe { ptr.add(4) };

            return Some((ptr, Address::IPv4(addr)));
        } else if rtnl_attr.rta_len == 20 {
            // IPV6 Address
            let octets = unsafe { std::mem::transmute::<*const u8, &[u8; 16]>(ptr) };
            let addr = std::net::Ipv6Addr::from(*octets);
            let ptr = unsafe { ptr.add(16) };

            return Some((ptr, Address::IPv6(addr)));
        } else if rtnl_attr.rta_len == 10 {
            // Hardware Address (LinkAddr/MacAddr)
            let octets = unsafe { std::mem::transmute::<*const u8, &[u8; 6]>(ptr) };
            let ptr = unsafe { ptr.add(6) };

            return Some((ptr, Address::Link(*octets)));
        } else {
            return None;
        }
    }

    fn next_nlattr(&mut self) -> Option<Result<Neighbour, io::Error>> {
        if self.packet_len == 0 {
            return None;
        }

        match self.packet_ptr {
            Some(ptr) => unsafe {
                let nl_attr = std::mem::transmute::<*const u8, &sys::nlattr>(ptr);

                let nl_attr_len = sys::align(nl_attr.nla_len as usize);
                self.packet_len -= nl_attr_len;
                let next_nl_attr_ptr = unsafe { ptr.add(nl_attr_len) };

                if nl_attr.nla_type != 0 {
                    self.packet_ptr = Some(next_nl_attr_ptr);
                    return self.next_nlattr();
                }

                let ptr = ptr.add(std::mem::size_of::<sys::nlattr>());
                let ptr = ptr.add(std::mem::size_of::<sys::prefixmsg>() * 2);
                
                let (ptr, src_addr) = self.read_rtattr(ptr)?;
                let (ptr, dst_addr) = self.read_rtattr(ptr)?;

                let record = Neighbour {
                    ifindex: self.ifindex,
                    dst_addr: src_addr,
                    hw_addr: dst_addr,
                };

                self.packet_ptr = Some(next_nl_attr_ptr);

                return Some(Ok(record))
            },
            None => None,
        }

    }
}


impl<'a, 'b> Iterator for Neighbours<'a, 'b> {
    type Item = Result<Neighbour, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done {
            return None;
        }

        if self.packet_ptr.is_none() {
            res2opt!(self.next_packet());
        }

        if self.packet_ptr.is_none() {
            self.is_done = true;
            return None;
        }

        self.next_nlattr()
    }
}


impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Address::IPv4(addr) => std::fmt::Debug::fmt(&addr, f),
            Address::IPv6(addr) => std::fmt::Debug::fmt(&addr, f),
            Address::Link(addr) => {
                write!(f, "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    addr[0],
                    addr[1],
                    addr[2],
                    addr[3],
                    addr[4],
                    addr[5])
            },
        }
    }
}