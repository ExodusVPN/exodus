
/// OSI Model Layer 4 
// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#[derive(Debug, PartialEq, Eq)]
pub enum Protocol {
    IPv4,
    /// Internet Control Message
    ICMP,
    /// Internet Group Management
    IGMP,
    
    IPv6,
    /// Routing Header for IPv6
    IPv6Route,
    /// Fragment Header for IPv6
    IPv6Frag,
    /// ICMP for IPv6 ( ICMPv6 )
    IPv6ICMP,
    /// No Next Header for IPv6
    IPv6NoNxt,
    /// Destination Options for IPv6
    IPv6Opts,
    /// IPv6 Hop-by-Hop Option
    HopOpt,

    /// Transmission Control
    TCP,
    /// User Datagram
    UDP,

    Unknow(u8)
}

impl Protocol {
    pub fn from_u8(n: u8) -> Result<Self, ::std::io::Error> {
        use self::Protocol::*;
        match n {
            0x04 => Ok(IPv4),
            0x01 => Ok(ICMP),
            0x02 => Ok(IGMP),
            0x29 => Ok(IPv6),
            0x2B => Ok(IPv6Route),
            0x2C => Ok(IPv6Frag),
            0x3A => Ok(IPv6ICMP),
            0x3B => Ok(IPv6NoNxt),
            0x3C => Ok(IPv6Opts),
            0x00 => Ok(HopOpt),
            0x06 => Ok(TCP),
            0x11 => Ok(UDP),
            _ => Ok(Unknow(n))
        }
    }

    pub fn to_u8(&self) -> u8 {
        use self::Protocol::*;
        match *self {
            IPv4 => 0x04,
            ICMP => 0x01,
            IGMP => 0x02,
            IPv6 => 0x29,
            IPv6Route => 0x2B,
            IPv6Frag  => 0x2C,
            IPv6ICMP  => 0x3A,
            IPv6NoNxt => 0x3B,
            IPv6Opts  => 0x3C,
            HopOpt    => 0x00,
            TCP  => 0x06,
            UDP  => 0x11,
            Unknow(n) => n
        }
    }
}