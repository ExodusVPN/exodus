use crate::sys;
use crate::packet::neighbour::{MacAddr, AddressFamily};

use byteorder::{ByteOrder, NativeEndian};

use std::io;
use std::mem;
use core::ops::Range;
use std::convert::TryFrom;


// rtm_type
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum RouteType {
    UNSPEC = 0,
    UNICAST,
    LOCAL,
    BROADCAST,
    ANYCAST,
    MULTICAST,
    BLACKHOLE,
    UNREACHABLE,
    PROHIBIT,
    THROW,
    NAT,
    XRESOLVE = 12,
}

impl TryFrom<u8> for RouteType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        use self::RouteType::*;

        match value {
            0 ..= 12 => {
                let v = unsafe { std::mem::transmute::<u8, RouteType>(value) };
                Ok(v)
            },
            _  => Err(()),
        }
    }
}

// rtm_protocol
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum RouteProtocol {
    UNSPEC = 0,
    REDIRECT,
    KERNEL,
    BOOT,
    STATIC = 4,
    GATED = 8,
    RA,
    MRT,
    ZEBRA,
    BIRD,
    DNROUTED,
    XORP,
    NTK,
    DHCP,
    MROUTED = 17,
    BABEL = 42,
}

impl TryFrom<u8> for RouteProtocol {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        use self::RouteProtocol::*;

        match value {
            0 ..= 4
            | 8 ..= 17
            | 42 => {
                let v = unsafe { std::mem::transmute::<u8, RouteProtocol>(value) };
                Ok(v)
            },
            _  => Err(()),
        }
    }
}

// rtm_scope
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum RouteScope {
    UNIVERSE =   0,
    SITE     = 200,
    LINK     = 253,
    HOST     = 254,
    NOWHERE  = 255,
}

impl TryFrom<u8> for RouteScope {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        use self::RouteScope::*;

        match value {
              0 => Ok(UNIVERSE),
            200 => Ok(SITE),
            253 => Ok(LINK),
            254 => Ok(HOST),
            255 => Ok(NOWHERE),
            _   => Err(()),
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum RouteTable {
    UNSPEC  = 0,
    COMPAT  = 252,
    DEFAULT = 253,
    MAIN    = 254,
    LOCAL   = 255,
}

impl TryFrom<u8> for RouteTable {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        use self::RouteTable::*;

        match value {
              0 => Ok(UNSPEC),
            252 => Ok(COMPAT),
            253 => Ok(DEFAULT),
            254 => Ok(MAIN),
            255 => Ok(LOCAL),
            _   => Err(()),
        }
    }
}

// rtm_flags
bitflags! {
    pub struct RouteFlags: u32 {
        const NOTIFY       =  0x100; // Notify user of route change
        const CLONED       =  0x200; // This route is cloned
        const EQUALIZE     =  0x400; // Multipath equalizer: NI
        const PREFIX       =  0x800; // Prefix addresses
        const LOOKUP_TABLE = 0x1000; // set rtm_table to FIB lookup result
    }
}


// 12
// Definitions used in routing table administration.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rtmsg {
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,
    pub rtm_table: u8,    // Routing table id
    pub rtm_protocol: u8, // Routing protocol; see below
    pub rtm_scope: u8,    // See below
    pub rtm_type: u8,     // See below
    pub rtm_flags: u32,
}




const FAMILY: usize         = 0;
const DST_LEN: usize        = 1;
const SRC_LEN: usize        = 2;
const TOS: usize            = 3;
const TABLE: usize          = 4;
const PROTOCOL: usize       = 5;
const SCOPE: usize          = 6;
const TYPE: usize           = 7;
const FLAGS: Range<usize>   = 8..12;

const PAYLOAD: usize        = 12;

#[derive(Debug, PartialEq, Clone)]
pub struct RoutePacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> RoutePacket<T> {
    pub const MIN_SIZE: usize = 12 + 4 + 4 + 4 + 6;

    #[inline]
    pub fn new_unchecked(buffer: T) -> RoutePacket<T> {
        RoutePacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<RoutePacket<T>, io::Error> {
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

        // if data.len() < self.total_len() {
        //     return Err(io::Error::new(io::ErrorKind::InvalidData, "packet is too small."));
        // }

        Ok(())
    }

    #[inline]
    pub fn family(&self) -> AddressFamily {
        let data = self.buffer.as_ref();
        AddressFamily::try_from(data[FAMILY]).unwrap()
    }

    #[inline]
    pub fn dst_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[DST_LEN]
    }

    #[inline]
    pub fn src_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[SRC_LEN]
    }

    #[inline]
    pub fn tos(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[TOS]
    }

    #[inline]
    pub fn table(&self) -> RouteTable {
        let data = self.buffer.as_ref();
        RouteTable::try_from(data[TABLE]).unwrap()
    }

    #[inline]
    pub fn protocol(&self) -> RouteProtocol {
        let data = self.buffer.as_ref();
        RouteProtocol::try_from(data[PROTOCOL]).unwrap()
    }

    #[inline]
    pub fn scope(&self) -> RouteScope {
        let data = self.buffer.as_ref();
        RouteScope::try_from(data[SCOPE]).unwrap()
    }

    #[inline]
    pub fn kind(&self) -> RouteType {
        let data = self.buffer.as_ref();
        RouteType::try_from(data[TYPE]).unwrap()
    }

    #[inline]
    pub fn flags(&self) -> RouteFlags {
        let data = self.buffer.as_ref();
        RouteFlags::from_bits_truncate(NativeEndian::read_u32(&data[FLAGS]))
    }
}



impl<'a, T: AsRef<[u8]> + ?Sized> RoutePacket<&'a T> {
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        // &data[PAYLOAD..self.total_len()]
        &data[PAYLOAD..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RoutePacket<T> {
    #[inline]
    pub fn set_family(&mut self, value: AddressFamily) {
        let data = self.buffer.as_mut();
        data[FAMILY] = value as u8;
    }
}


impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for RoutePacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RoutePacket {{ family: {:?}, dst_len: {}, src_len: {}, tos: {}, table: {:?}, protocol: {:?}, scope: {:?}, kind: {:?}, flags: {:?}, attrs: {:?} }}",
                self.family(),
                self.dst_len(),
                self.src_len(),
                self.tos(),
                self.table(),
                self.protocol(),
                self.scope(),
                self.kind(),
                self.flags(),
                self.payload())
    }
}
