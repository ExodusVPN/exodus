
use std::net::{Ipv4Addr, Ipv6Addr};

// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#[deriving(Debug, Eq)]
pub enum Protocol {
    ICMP,
    IGMP,
    TCP,
    UDP,
    RDP,
    IPv6,
    SDRP,
    IPv6Route,
    IPv6Frag,
    IPv6ICMP,
    IPv6NoNxt,
    IPv6Opts,
    L2TP,
    UDPLite,
    Unknow(u8)
}

impl Protocol {
    pub fn from_u8(n: u8) -> Result<Self, ::std::io::Error> {
        use self::Protocol::*;
        match n {
            0x00 => Ok(ICMP),
            0x02 => Ok(IGMP),
            0x06 => Ok(TCP),
            0x11 => Ok(UDP),
            0x29 => Ok(IPv6),
            0x2B => Ok(IPv6Route),
            0x2C => Ok(IPv6Frag),
            0x3A => Ok(IPv6ICMP),
            0x3B => Ok(IPv6NoNxt),
            0x3C => Ok(IPv6Opts),
            0x73 => Ok(L2TP),
            0x88 => Ok(UDPLite),
            _ => Ok(Unknow(n))
        }
    }

    pub fn to_u8(&self) -> u8 {
        use self::Protocol::*;
        match *self {
            ICMP => 0x00,
            IGMP => 0x02,
            TCP  => 0x06,
            UDP  => 0x11,
            IPv6 => 0x29,
            IPv6Route => 0x2B,
            IPv6Frag  => 0x2C,
            IPv6ICMP  => 0x3A,
            IPv6NoNxt => 0x3B,
            IPv6Opts  => 0x3C,
            L2TP      => 0x73,
            UDPLite   => 0x88,
            Unknow(n) => n
    }
}

// https://en.wikipedia.org/wiki/IPv4#Packet_structure
#[derive(Debug)]
pub struct IPv4Packet {
    version: u8,         //  4 bits
    ihl : u8,            //  4 bits
    dscp: u8,            //  6 bits
    ecn: u8,             //  2 bits
    total_length: u16,   // 16 bits
    identification: u16, // 16 bits
    flags: u8,           //  3 bits
    fragment_offset: u16,// 13 bits
    time_to_live: u8,    //  8 bits
    protocol: Protocol,  //  8 bits
    header_checksum: u16,// 16 bits
    src_ip: Ipv4Addr,    // 32 bits
    dst_ip: Ipv4Addr,    // 32 bits
    options: Option<[u8; 12]>    // 0 - 96 bits, start 160, end 256, if IHL >= 5
}


// https://en.wikipedia.org/wiki/IPv6_packet
#[derive(Debug)]
pub struct IPv6Packet {
    version: u8,         //  4 bits
    traffic_class: u8,   //  8 bits
    flow_label: u32,     // 20 bits
    payload_length: u16, // 16 bits
    next_header: u8,     //  8 bits
    hoplimit: u8,        //  8 bits
    src_ip  : u128,      // 128 bits
    dst_ip  : u128,      // 128 bits
}

impl IPv4Packet {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!();
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }

    pub fn checksum(&self) -> u16 {
        unimplemented!();
    }
}

impl IPv6Packet {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!();
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
}

