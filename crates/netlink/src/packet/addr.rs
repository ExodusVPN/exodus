// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_addr.h

use crate::packet::RouteScope;
use crate::packet::AddressFamily;

use byteorder::{ByteOrder, NativeEndian};

use std::io;
use core::ops::Range;


#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ifaddrmsg {
    pub ifa_family: u8,
    pub ifa_prefixlen: u8, // The prefix length
    pub ifa_flags: u8,     // Flags
    pub ifa_scope: u8,     // Address scope
    pub ifa_index: u32,    // Link index
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ifa_cacheinfo {
    pub ifa_prefered: u32,
    pub ifa_valid: u32,
    pub cstamp: u32,       // created timestamp, hundredths of seconds
    pub tstamp: u32,       // updated timestamp, hundredths of seconds
}


// ifa_flags
bitflags! {
    pub struct AddrFlags: u8 {
        const IFA_F_SECONDARY       = 0x01;
        const IFA_F_TEMPORARY       = Self::IFA_F_SECONDARY.bits;

        const IFA_F_NODAD           = 0x02;
        const IFA_F_OPTIMISTIC      = 0x04;
        const IFA_F_DADFAILED       = 0x08;
        const IFA_F_HOMEADDRESS     = 0x10;
        const IFA_F_DEPRECATED      = 0x20;
        const IFA_F_TENTATIVE       = 0x40;
        const IFA_F_PERMANENT       = 0x80;
        // const IFA_F_MANAGETEMPADDR  = 0x100;
        // const IFA_F_NOPREFIXROUTE   = 0x200;
        // const IFA_F_MCAUTOJOIN      = 0x400;
        // const IFA_F_STABLE_PRIVACY  = 0x800;
    }
}


#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct AddrAttrType(pub u16);

impl AddrAttrType {
    pub const IFA_UNSPEC: Self         = Self(0);
    pub const IFA_ADDRESS: Self        = Self(1);
    pub const IFA_LOCAL: Self          = Self(2);
    pub const IFA_LABEL: Self          = Self(3);
    pub const IFA_BROADCAST: Self      = Self(4);
    pub const IFA_ANYCAST: Self        = Self(5);
    pub const IFA_CACHEINFO: Self      = Self(6);
    pub const IFA_MULTICAST: Self      = Self(7);
    pub const IFA_FLAGS: Self          = Self(8);
    pub const IFA_RT_PRIORITY: Self    = Self(9);  // u32, priority/metric for prefix route
    pub const IFA_TARGET_NETNSID: Self = Self(10);
}

impl std::fmt::Debug for AddrAttrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IFA_UNSPEC => write!(f, "IFA_UNSPEC"),
            Self::IFA_ADDRESS => write!(f, "IFA_ADDRESS"),
            Self::IFA_LOCAL => write!(f, "IFA_LOCAL"),
            Self::IFA_LABEL => write!(f, "IFA_LABEL"),
            Self::IFA_BROADCAST => write!(f, "IFA_BROADCAST"),
            Self::IFA_ANYCAST => write!(f, "IFA_ANYCAST"),
            Self::IFA_CACHEINFO => write!(f, "IFA_CACHEINFO"),
            Self::IFA_MULTICAST => write!(f, "IFA_MULTICAST"),
            Self::IFA_FLAGS => write!(f, "IFA_FLAGS"),
            Self::IFA_RT_PRIORITY => write!(f, "IFA_RT_PRIORITY"),
            Self::IFA_TARGET_NETNSID => write!(f, "IFA_TARGET_NETNSID"),
            _ => write!(f, "IFA_UNKNOW({})", self.0),
        }
    }
}

impl std::fmt::Display for AddrAttrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}


const FAMILY: usize         = 0;
const PREFIX_LEN: usize     = 1;
const FLAGS: usize          = 2;
const SCOPE: usize          = 3;
const IFINDEX: Range<usize> = 4..8;
const PAYLOAD: usize        = 8;

#[derive(Debug, PartialEq, Clone)]
pub struct AddrPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> AddrPacket<T> {
    pub const MIN_SIZE: usize = 8;

    #[inline]
    pub fn new_unchecked(buffer: T) -> AddrPacket<T> {
        AddrPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<AddrPacket<T>, io::Error> {
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

        Ok(())
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    #[inline]
    pub fn family(&self) -> AddressFamily {
        let data = self.buffer.as_ref();
        AddressFamily(data[FAMILY])
    }

    #[inline]
    pub fn prefixlen(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[PREFIX_LEN]
    }

    #[inline]
    pub fn flags(&self) -> AddrFlags {
        let data = self.buffer.as_ref();
        AddrFlags::from_bits_truncate(data[FLAGS])
    }

    #[inline]
    pub fn scope(&self) -> RouteScope {
        let data = self.buffer.as_ref();
        RouteScope(data[SCOPE])
    }

    #[inline]
    pub fn ifindex(&self) -> i32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_i32(&data[IFINDEX])
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        Self::MIN_SIZE
    }
}


impl<'a, T: AsRef<[u8]> + ?Sized> AddrPacket<&'a T> {
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[PAYLOAD..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AddrPacket<T> {
    #[inline]
    pub fn set_family(&mut self, value: AddressFamily) {
        let data = self.buffer.as_mut();
        data[FAMILY] = value.0;
    }

    #[inline]
    pub fn set_prefixlen(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[PREFIX_LEN] = value;
    }

    #[inline]
    pub fn set_flags(&mut self, value: AddrFlags) {
        let data = self.buffer.as_mut();
        data[FLAGS] = value.bits();
    }

    #[inline]
    pub fn set_scope(&mut self, value: RouteScope) {
        let data = self.buffer.as_mut();
        data[SCOPE] = value.0;
    }

    #[inline]
    pub fn set_ifindex(&mut self, value: i32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_i32(&mut data[IFINDEX], value)
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8]{
        let data = self.buffer.as_mut();
        &mut data[PAYLOAD..]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for AddrPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AddrPacket {{ family: {:?}, prefixlen: {}, flags: {:?}, scope: {:?}, ifindex: {:?} }}",
                self.family(),
                self.prefixlen(),
                self.flags(),
                self.scope(),
                self.ifindex())
    }
}