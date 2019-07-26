use crate::sys;

use byteorder::{ByteOrder, NativeEndian};

use std::io;
use std::mem;
use core::ops::Range;
use std::convert::TryFrom;

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

#[repr(i32)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Protocol {
    Route     = 0,
    Netfilter = 12,
}

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Kind {
    // control messages
    Noop    = 1, // Nothing
    Error   = 2, // Error
    Done    = 3, // End of a dump
    Overrun = 4, // Data lost

    // Protocol Method
    NewLink = 16,
    DelLink = 17,
    GetLink = 18,
    SetLink = 19,
    
    NewAddr = 20,
    DelAddr = 21,
    GetAddr = 22,
    
    NewRoute = 24,
    DelRoute = 25,
    GetRoute = 26,
    
    NewNeigh = 28,
    DelNeigh = 29,
    GetNeigh = 30,
    
    NewRule  = 32,
    DelRule  = 33,
    GetRule  = 34,
}


impl Kind {
    pub fn is_reserved(&self) -> bool {
        false
    }

    pub fn is_control(&self) -> bool {
        use self::Kind::*;

        match *self {
            Noop | Error | Done | Overrun => true,
            _ => false,
        }
    }

    pub fn is_err(&self) -> bool {
        use self::Kind::*;

        match *self {
            Error | Overrun => true,
            _ => false,
        }
    }

    pub fn is_done(&self) -> bool {
        use self::Kind::*;

        match *self {
            Done => true,
            _ => false,
        }
    }
}

impl Into<u16> for Kind {
    fn into(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for Kind {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, ()> {
        match value {
            // < 0x10: reserved control messages
            0 | 5 ..= 15 => Err(()),
               1 ..=  4
            | 16 ..= 19
            | 20 ..= 22
            | 24 ..= 26
            | 28 ..= 30
            | 32 ..= 34 => {
                let v = unsafe { std::mem::transmute::<u16, Kind>(value) };
                Ok(v)
            },
            _  => Err(()),
        }
    }
}


bitflags! {
    pub struct Flags: u16 {
        const REQUEST       =  1; // It is request message.
        const MULTI         =  2; // Multipart message, terminated by 
        const ACK           =  4; // Reply with ack, with zero or error 
        const ECHO          =  8; // Echo this request
        const DUMP_INTR     = 16; // Dump was inconsistent due to sequence 
        const DUMP_FILTERED = 32; // Dump was filtered as 
        // Modifiers to GET request
        const ROOT   = 0x100;                    // specify tree root
        const MATCH  = 0x200;                    // return all matching
        const ATOMIC = 0x400;                    // atomic GET
        const DUMP   = Self::ROOT.bits | Self::MATCH.bits;
        // Modifiers to NEW request
        const REPLACE = 0x100;   // Override existing
        const EXCL    = 0x200;   // Do not touch, if it exists
        const CREATE  = 0x400;   // Create, if it does not 
        const APPEND  = 0x800;   // Add to end of list
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

        if let Err(e) = Kind::try_from(self.kind_raw()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Netlink Message Type is unknow."));
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
    pub fn kind_raw(&self) -> u16 {
        let data = self.buffer.as_ref();
        NativeEndian::read_u16(&data[KIND])
    }

    #[inline]
    pub fn kind(&self) -> Kind {
        Kind::try_from(self.kind_raw()).unwrap()
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
        sys::align(self.len() as usize)
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
        NativeEndian::write_u16(&mut data[KIND], value.into())
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