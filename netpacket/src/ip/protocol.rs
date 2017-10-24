
/// OSI Model Layer 4 
// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#[derive(Debug, PartialEq, Eq)]
pub enum Protocol {
    ICMP,
    IGMP,
    TCP,
    UDP,
    IPv6,
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
}