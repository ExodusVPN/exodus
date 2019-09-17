use super::align;

use byteorder::{ByteOrder, NativeEndian};

use std::io;
use core::ops::Range;

// https://tools.ietf.org/html/rfc3549#section-2.2
// Message Format
// There are three levels to a Netlink message: The general Netlink
// message header, the IP service specific template, and the IP service
// specific data.
// 
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                   Netlink message header                      |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                  IP Service Template                          |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                  IP Service specific data in TLVs             |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 
// The Netlink message is used to communicate between the FEC and CPC
// for parameterization of the FECs, asynchronous event notification of
// FEC events to the CPCs, and statistics querying/gathering (typically
// by a CPC).
// 
// The Netlink message header is generic for all services, whereas the
// IP Service Template header is specific to a service.  Each IP Service
// then carries parameterization data (CPC->FEC direction) or response
// (FEC->CPC direction).  These parameterizations are in TLV (Type-
// Length-Value) format and are unique to the service.
// 
// The different parts of the netlink message are discussed in the
// following sections.
// 
// Netlink Message Header
// https://tools.ietf.org/html/rfc3549#section-2.3.2
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Length                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |            Type              |           Flags              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Process ID (PID)                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 

// 16 bytes
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nlmsghdr {
    // Length of message including header
    pub nlmsg_len: u32,
    // Type of message content: RTM_GETNEIGH, ...
    pub nlmsg_type: u16,
    // Additional flags: NLM_F_DUMP, NLM_F_REQUEST, ...
    pub nlmsg_flags: u16,
    // Sequence number
    pub nlmsg_seq: u32,
    // Sending process port ID
    pub nlmsg_pid: u32,
}

impl Default for nlmsghdr {
    fn default() -> Self {
        Self {
            nlmsg_len: std::mem::size_of::<Self>() as u32,
            nlmsg_type: 0,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct nl_mmap_req {
    pub nm_block_size: u32,
    pub nm_block_nr: u32,
    pub nm_frame_size: u32,
    pub nm_frame_nr: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct nl_mmap_hdr {
    pub nm_status: u32,
    pub nm_len: u32,
    pub nm_group: u32,
    // credentials
    pub nm_pid: u32,
    pub nm_uid: u32,
    pub nm_gid: u32,
}


#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct Protocol(pub i32);

impl Protocol {
    pub const NETLINK_ROUTE: Self     = Self(0);
    pub const NETLINK_NETFILTER: Self = Self(12);
}

impl std::fmt::Debug for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::NETLINK_ROUTE => write!(f, "NETLINK_ROUTE"),
            Self::NETLINK_NETFILTER => write!(f, "NETLINK_NETFILTER"),
            _ => write!(f, "NETLINK_PROTOCOL_UNKNOW({})", self.0),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Into<i32> for Protocol {
    fn into(self) -> i32 {
        self.0
    }
}


#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct Kind(pub u16);

impl Kind {
    // Netlink Control Message
    pub const NLMSG_NOOP: Self    = Self(0x1); // Nothing
    pub const NLMSG_ERROR: Self   = Self(0x2); // Error
    pub const NLMSG_DONE: Self    = Self(0x3); // End of a dump
    pub const NLMSG_OVERRUN: Self = Self(0x4); // Data lost

    // Netlink Message Type
    pub const RTM_NEWLINK: Self = Self(16);
    pub const RTM_DELLINK: Self = Self(17);
    pub const RTM_GETLINK: Self = Self(18);
    pub const RTM_SETLINK: Self = Self(19);

    pub const RTM_NEWADDR: Self = Self(20);
    pub const RTM_DELADDR: Self = Self(21);
    pub const RTM_GETADDR: Self = Self(22);

    pub const RTM_NEWROUTE: Self = Self(24);
    pub const RTM_DELROUTE: Self = Self(25);
    pub const RTM_GETROUTE: Self = Self(26);

    pub const RTM_NEWNEIGH: Self = Self(28);
    pub const RTM_DELNEIGH: Self = Self(29);
    pub const RTM_GETNEIGH: Self = Self(30);

    pub const RTM_NEWRULE: Self  = Self(32);
    pub const RTM_DELRULE: Self  = Self(33);
    pub const RTM_GETRULE: Self  = Self(34);

    #[inline]
    pub fn is_reserved(&self) -> bool {
        // < 0x10: reserved control messages
        *self < Self(0x10) && !self.is_control()
    }

    #[inline]
    pub fn is_control(&self) -> bool {
        *self == Self::NLMSG_NOOP
        || *self == Self::NLMSG_ERROR
        || *self == Self::NLMSG_DONE
        || *self == Self::NLMSG_OVERRUN
    }

    #[inline]
    pub fn is_err(&self) -> bool {
        *self == Self::NLMSG_ERROR
    }

    #[inline]
    pub fn is_done(&self) -> bool {
        *self == Self::NLMSG_DONE
    }
}

impl std::fmt::Debug for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::NLMSG_NOOP => write!(f, "NLMSG_NOOP"),
            Self::NLMSG_ERROR => write!(f, "NLMSG_ERROR"),
            Self::NLMSG_DONE => write!(f, "NLMSG_DONE"),
            Self::NLMSG_OVERRUN => write!(f, "NLMSG_OVERRUN"),

            Self::RTM_NEWLINK => write!(f, "RTM_NEWLINK"),
            Self::RTM_DELLINK => write!(f, "RTM_DELLINK"),
            Self::RTM_GETLINK => write!(f, "RTM_GETLINK"),
            Self::RTM_SETLINK => write!(f, "RTM_SETLINK"),

            Self::RTM_NEWADDR => write!(f, "RTM_NEWADDR"),
            Self::RTM_DELADDR => write!(f, "RTM_DELADDR"),
            Self::RTM_GETADDR => write!(f, "RTM_GETADDR"),

            Self::RTM_NEWROUTE => write!(f, "RTM_NEWROUTE"),
            Self::RTM_DELROUTE => write!(f, "RTM_DELROUTE"),
            Self::RTM_GETROUTE => write!(f, "RTM_GETROUTE"),

            Self::RTM_NEWNEIGH => write!(f, "RTM_NEWNEIGH"),
            Self::RTM_DELNEIGH => write!(f, "RTM_DELNEIGH"),
            Self::RTM_GETNEIGH => write!(f, "RTM_GETNEIGH"),

            Self::RTM_NEWRULE => write!(f, "RTM_NEWRULE"),
            Self::RTM_DELRULE => write!(f, "RTM_DELRULE"),
            Self::RTM_GETRULE => write!(f, "RTM_GETRULE"),

            _ => write!(f, "RTM_UNKNOW({})", self.0),
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Into<u16> for Kind {
    fn into(self) -> u16 {
        self.0
    }
}



bitflags! {
    pub struct Flags: u16 {
        const NLM_F_REQUEST       =  1; // It is request message.
        const NLM_F_MULTI         =  2; // Multipart message, terminated by 
        const NLM_F_ACK           =  4; // Reply with ack, with zero or error 
        const NLM_F_ECHO          =  8; // Echo this request
        const NLM_F_DUMP_INTR     = 16; // Dump was inconsistent due to sequence 
        const NLM_F_DUMP_FILTERED = 32; // Dump was filtered as 
        // Modifiers to GET request
        const NLM_F_ROOT   = 0x100;     // specify tree root
        const NLM_F_MATCH  = 0x200;     // return all matching
        const NLM_F_ATOMIC = 0x400;     // atomic GET
        const NLM_F_DUMP   = Self::NLM_F_ROOT.bits | Self::NLM_F_MATCH.bits;
        // Modifiers to NEW request
        const NLM_F_REPLACE = 0x100;   // Override existing
        const NLM_F_EXCL    = 0x200;   // Do not touch, if it exists
        const NLM_F_CREATE  = 0x400;   // Create, if it does not 
        const NLM_F_APPEND  = 0x800;   // Add to end of list
    }
}

impl Into<u16> for Flags {
    fn into(self) -> u16 {
        self.bits()
    }
}


const LEN:     Range<usize> = 0..4;
const KIND:    Range<usize> = 4..6;
const FLAGS:   Range<usize> = 6..8;
const SEQ:     Range<usize> = 8..12;
const PID:     Range<usize> = 12..16;
const PAYLOAD: usize        = 16;


#[derive(Debug, PartialEq, Clone)]
pub struct NetlinkPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> NetlinkPacket<T> {
    pub const MIN_SIZE: usize = 16;

    #[inline]
    pub fn new_unchecked(buffer: T) -> NetlinkPacket<T> {
        NetlinkPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<NetlinkPacket<T>, io::Error> {
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
    pub fn into_inner(self) -> T {
        self.buffer
    }

    #[inline]
    pub fn len(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[LEN])
    }

    #[inline]
    pub fn kind(&self) -> Kind {
        let data = self.buffer.as_ref();
        Kind(NativeEndian::read_u16(&data[KIND]))
    }

    #[inline]
    pub fn flags(&self) -> Flags {
        let data = self.buffer.as_ref();
        Flags::from_bits_truncate(NativeEndian::read_u16(&data[FLAGS]))
    }

    #[inline]
    pub fn seq(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[SEQ])
    }

    #[inline]
    pub fn pid(&self) -> u32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u32(&data[PID])
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        Self::MIN_SIZE
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        align(self.len() as usize)
    }

    #[inline]
    pub fn payload_len(&self) -> usize {
        self.total_len() - self.header_len()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> NetlinkPacket<&'a T> {
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[PAYLOAD..self.total_len()]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NetlinkPacket<T> {
    #[inline]
    pub fn set_len(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[LEN], value)
    }

    #[inline]
    pub fn set_kind(&mut self, value: Kind) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[KIND], value.0)
    }

    #[inline]
    pub fn set_flags(&mut self, value: Flags) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[FLAGS], value.bits())
    }

    #[inline]
    pub fn set_seq(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[SEQ], value)
    }

    #[inline]
    pub fn set_pid(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[PID], value)
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = PAYLOAD..self.total_len();
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for NetlinkPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NetlinkPacket {{ len: {:?}, kind: {}, flags: {:?}, seq: {:?}, pid: {:?}, payload: {:?} }}",
                self.len(),
                self.kind(),
                self.flags(),
                self.seq(),
                self.pid(),
                self.payload())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct NetlinkErrorPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> NetlinkErrorPacket<T> {
    pub const MIN_SIZE: usize = 4;

    #[inline]
    pub fn new_unchecked(buffer: T) -> NetlinkErrorPacket<T> {
        NetlinkErrorPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<NetlinkErrorPacket<T>, io::Error> {
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
    pub fn errorno(&self) -> i32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_i32(&data[0..4])
    }

    #[inline]
    pub fn err(&self) -> std::io::Error {
        std::io::Error::from_raw_os_error(self.errorno())
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NetlinkErrorPacket<T> {
    #[inline]
    pub fn set_errorno(&mut self, value: i32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_i32(&mut data[0..4], value)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for NetlinkErrorPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NetlinkErrorPacket {{ errorno: {:?}, err: {:?} }}",
                self.errorno(),
                self.err())
    }
}


#[derive(Debug, PartialEq, Clone)]
pub struct NetlinkAttrPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> NetlinkAttrPacket<T> {
    pub const MIN_SIZE: usize = 4;

    #[inline]
    pub fn new_unchecked(buffer: T) -> NetlinkAttrPacket<T> {
        NetlinkAttrPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<NetlinkAttrPacket<T>, io::Error> {
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

        if self.total_len() < Self::MIN_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "packet is too small."));
        }

        if data.len() < self.total_len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "packet is too small."));
        }

        Ok(())
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    #[inline]
    pub fn len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[0..2])
    }

    #[inline]
    pub fn kind(&self) -> u16 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[2..4])
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        4
    }

    #[inline]
    pub fn payload_len(&self) -> usize {
        self.total_len() - self.header_len()
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        align(self.len() as usize)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> NetlinkAttrPacket<&'a T> {
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[4..self.total_len()]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NetlinkAttrPacket<T> {
    #[inline]
    pub fn set_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[0..2], value)
    }

    #[inline]
    pub fn set_kind(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[2..4], value)
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let len = self.total_len();
        let data = self.buffer.as_mut();
        &mut data[4..len]
    }
}