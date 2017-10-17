
pub mod v4;
pub mod v6;


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

#[derive(Debug)]
pub enum IpPacket {
    V4(v4::Ipv4Packet),
    V6(v6::Ipv6Packet)
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

#[derive(Debug)]
pub struct TcpIpv4PseudoHeader{
    src_ip  : u32,
    dst_ip  : u32,
    zeroes  : u8,
    protocol: u8,
    tcp_length: u16,
    // TCP Packet
    // ...
}
#[derive(Debug)]
pub struct TcpIpv6PseudoHeader{
    src_ip     : u128,
    dst_ip     : u128,
    tcp_length : u32,
    zeroes     : u32,   // 24 bits
    next_header: u8,
    // TCP Packet
    // ...
}


#[derive(Debug)]
pub struct UdpIpv4PseudoHeader{
    src_ip  : u32,
    dst_ip  : u32,
    zeroes  : u8,
    protocol: u8,
    udp_length: u16,
    // UDP Packet
    // ...
}
#[derive(Debug)]
pub struct UdpIpv6PseudoHeader{
    src_ip     : u128,
    dst_ip     : u128,
    udp_length : u32,
    zeroes     : u32,   // 24 bits
    next_header: u8,
    // UDP Packet
    // ...
}



impl IpPacket {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        let first_byte: u8 = ;
        match payload[0] >> 4 {
            // TODO: TCP/IP checksum
            4u8 => match v4::Ipv4Packet::from_bytes(payload) {
                Ok(packet) => Ok(IpPacket::V4(packet)),
                Err(e)     => Err(e)
            },
            6u8 => match v6::Ipv6Packet::from_bytes(payload) {
                Ok(packet) => Ok(IpPacket::V6(packet)),
                Err(e)     => Err(e)
            },
            _ => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."))
        }
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        match *self {
            IpPacket::V4(packet) => packet.as_bytes(),
            IpPacket::V6(packet) => packet.as_bytes()
        }
    }

    pub fn tcp_ip_checksum(&self) -> bool {
        // https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation

    }
    pub fn udp_ip_checksum(&self) -> bool {
        // https://en.wikipedia.org/wiki/User_Datagram_Protocol#Checksum_computation

    }
}
