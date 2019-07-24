use crate::sys;

use byteorder::{ByteOrder, NativeEndian};

use std::io;
use std::mem;
use core::ops::Range;
use std::convert::TryFrom;


// Neighbor Setup Service Module
// 
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Family    |    Reserved1  |           Reserved2           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Interface Index                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           State             |     Flags     |     Type      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 
// Family: 8 bits
// Address Family: AF_INET for IPv4; and AF_INET6 for IPV6.
// 
// Interface Index: 32 bits
// The unique interface index.
// 
// State: 16 bits
// A bitmask of the following states:
//              NUD_INCOMPLETE   Still attempting to resolve.
//              NUD_REACHABLE    A confirmed working cache entry
//              NUD_STALE        an expired cache entry.
//              NUD_DELAY        Neighbor no longer reachable.
//                               Traffic sent, waiting for
//                               confirmation.
//              NUD_PROBE        A cache entry that is currently
//                               being re-solicited.
//              NUD_FAILED       An invalid cache entry.
//              NUD_NOARP        A device which does not do neighbor
//                               discovery (ARP).
//              NUD_PERMANENT    A static entry.
// Flags: 8 bits
//              NTF_PROXY        A proxy ARP entry.
//              NTF_ROUTER       An IPv6 router.
// 
// Attributes applicable to this service:
//              Attributes      Description
//              ------------------------------------
//              NDA_UNSPEC      Unknown type.
//              NDA_DST         A neighbour cache network.
//                              layer destination address
//              NDA_LLADDR      A neighbor cache link layer
//                              address.
//              NDA_CACHEINFO   Cache statistics.
// 
// Additional Netlink message types applicable to this service:
// RTM_NEWNEIGH, RTM_DELNEIGH, and RTM_GETNEIGH.
// 




#[repr(u8)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum AddressFamily {
    Ipv4 = 2,
    Ipv6 = 10,
}

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

const FAMILY: usize         = 0;
const IFINDEX: Range<usize> = 4..8;
const STATE:   Range<usize> = 8..10;
const FLAGS: usize          = 10;
const KIND: usize           = 11;
const PAYLOAD: usize        = 12;

// attrs
const SRC_ADDR_LEN: Range<usize> = 12..14;
// const DST_ADDR_LEN: Range<usize> = 


#[derive(Debug, PartialEq, Clone)]
pub struct NeighbourPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> NeighbourPacket<T> {
    pub const MIN_SIZE: usize = 12 + 4 + 4 + 4 + 6;

    #[inline]
    pub fn new_unchecked(buffer: T) -> NeighbourPacket<T> {
        NeighbourPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<NeighbourPacket<T>, io::Error> {
        let v = Self::new_unchecked(buffer);
        v.check_len()?;

        Ok(v)
    }

    #[inline]
    pub fn check_len(&self) -> Result<(), io::Error> {
        let data = self.buffer.as_ref();
        if data.len() < Self::MIN_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "packet is too small."));
        }

        if data.len() < self.total_len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "packet is too small."));
        }

        Ok(())
    }

    #[inline]
    pub fn family(&self) -> AddressFamily {
        // AF_INET  = 2
        // AF_INET6 = 10
        // AF_LLC   = 26
        let data = self.buffer.as_ref();
        match data[FAMILY] {
            2  => AddressFamily::Ipv4,
            10 => AddressFamily::Ipv6,
            n  => {
                unreachable!("Unknow address family: {:?}", n);
            },
        }
    }

    #[inline]
    pub fn ifindex(&self) -> i32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_i32(&data[IFINDEX])
    }

    #[inline]
    pub fn state(&self) -> NeighbourState {
        let data = self.buffer.as_ref();
        NeighbourState::from_bits_truncate(NativeEndian::read_u16(&data[STATE]))
    }

    #[inline]
    pub fn flags(&self) -> NeighbourFlags {
        let data = self.buffer.as_ref();
        NeighbourFlags::from_bits_truncate(data[FLAGS])
    }

    #[inline]
    pub fn kind(&self) -> NeighbourKind {
        let data = self.buffer.as_ref();
        // UNSPEC    = 0
        // DST       = 1
        // LLADDR    = 2
        // CACHEINFO = 3
        match data[KIND] {
            0 => NeighbourKind::UNSPEC,
            1 => NeighbourKind::DST,
            2 => NeighbourKind::LLADDR,
            3 => NeighbourKind::CACHEINFO,
            _ => unreachable!(),
        }
    }

    // Attrs
    #[inline]
    fn dst_addr_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[SRC_ADDR_LEN])
    }

    #[inline]
    fn link_addr_start(&self) -> usize {
        let dst_len = sys::align(self.dst_addr_len() as usize);
        PAYLOAD + dst_len
    }

    #[inline]
    fn link_addr_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        let start = self.link_addr_start();
        let end = start + 2;

        NativeEndian::read_u16(&data[start..end])
    }

    #[inline]
    pub fn dst_addr(&self) -> std::net::IpAddr {
        let data = self.buffer.as_ref();
        let len = self.dst_addr_len() as usize;
        match len {
            8 => {
                assert_eq!(self.family(), AddressFamily::Ipv4);
                // 12..14
                // 14..16
                // 16..20
                let octets = NativeEndian::read_u32(&data[16..20]);
                std::net::Ipv4Addr::from(octets).into()
            },
            10 => {
                // MacAddr
                unreachable!();
            },
            20 => {
                // 12..14
                // 14..16
                // 16..20
                assert_eq!(self.family(), AddressFamily::Ipv6);
                let octets = NativeEndian::read_u128(&data[16..32]);
                std::net::Ipv6Addr::from(octets).into()
            },
            _ => unreachable!(),
        }
    }

    #[inline]
    pub fn link_addr(&self) -> MacAddr {
        let data = self.buffer.as_ref();
        let start = self.link_addr_start() + 4;

        debug_assert!(self.link_addr_len() >= 10);

        MacAddr([
            data[start+0], data[start+1], data[start+2],
            data[start+3], data[start+4], data[start+5],
        ])
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        12
    }

    // attr list len
    #[inline]
    pub fn payload_len(&self) -> usize {
        let data = self.buffer.as_ref();
        let data_len = data.len();

        let mut offset = PAYLOAD;
        loop {
            if offset >= data_len {
                break;
            }

            if data_len - offset < 8  {
                offset = data_len;
                break;
            }

            let attr_len = NativeEndian::read_u16(&data[offset..offset+2]);
            let len = sys::align(attr_len as usize);
            offset += len;
        }

        offset - PAYLOAD
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }
}


impl<'a, T: AsRef<[u8]> + ?Sized> NeighbourPacket<&'a T> {
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[PAYLOAD..self.total_len()]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NeighbourPacket<T> {
    #[inline]
    pub fn set_family(&mut self, value: AddressFamily) {
        let data = self.buffer.as_mut();
        data[FAMILY] = value as u8;
    }

    #[inline]
    pub fn set_ifindex(&mut self, value: i32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_i32(&mut data[IFINDEX], value);
    }

    #[inline]
    pub fn set_state(&mut self, value: NeighbourState) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[STATE], value.bits());
    }

    #[inline]
    pub fn set_flags(&mut self, value: NeighbourFlags) {
        let data = self.buffer.as_mut();
        data[FLAGS] = value.bits();
    }

    #[inline]
    pub fn set_kind(&mut self, value: NeighbourKind) {
        let data = self.buffer.as_mut();
        data[KIND] = value as u8;
    }

    #[inline]
    pub fn set_dst_addr(&mut self, value: std::net::IpAddr) {
        match value {
            std::net::IpAddr::V4(v4_addr) => {
                self.set_family(AddressFamily::Ipv4);

                let data = self.buffer.as_mut();
                let octets = v4_addr.octets();
                // 8, 0, 1, 0,
                data[PAYLOAD+0] = 8;
                data[PAYLOAD+1] = 0;
                data[PAYLOAD+2] = 1;
                data[PAYLOAD+3] = 0;

                data[PAYLOAD+4] = octets[0];
                data[PAYLOAD+5] = octets[1];
                data[PAYLOAD+6] = octets[2];
                data[PAYLOAD+7] = octets[3];
            },
            std::net::IpAddr::V6(v6_addr) => {
                self.set_family(AddressFamily::Ipv6);

                let data = self.buffer.as_mut();
                let octets = v6_addr.octets();
                // 20, 0, 1, 0,
                data[PAYLOAD+0] = 20;
                data[PAYLOAD+1] = 0;
                data[PAYLOAD+2] = 1;
                data[PAYLOAD+3] = 0;

                let start = PAYLOAD + 4;
                let end = start + 16;
                &mut data[start..end].copy_from_slice(&octets);
            }
        }
    }

    #[inline]
    pub fn set_link_addr(&mut self, value: MacAddr) {
        let start = self.link_addr_start();

        let data = self.buffer.as_mut();

        // 10, 0, 2, 0,
        data[start+0] = 10;
        data[start+1] = 0;
        data[start+2] = 2;
        data[start+3] = 0;

        let start = start + 4;
        let end = start + 6;
        &mut data[start..end].copy_from_slice(&value.0);
    }
}



#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct MacAddr(pub [u8; 6]);


impl std::fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let addr = self.0;
        write!(f, "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    addr[0],
                    addr[1],
                    addr[2],
                    addr[3],
                    addr[4],
                    addr[5])
    }
}