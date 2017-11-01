
use byteorder::{BigEndian, ReadBytesExt, ByteOrder};

use std::mem::transmute;

use super::{Options, Codepoint, ToS};

/// [RFC-791](https://tools.ietf.org/html/rfc791#page-11) , September 1981
///
/// 3.1.  Internet Header Format
///
///   A summary of the contents of the internet header follows:
///
///
///     0                   1                   2                   3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |Version|  IHL  |Type of Service|          Total Length         |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |         Identification        |Flags|      Fragment Offset    |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |  Time to Live |    Protocol   |         Header Checksum       |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |                       Source Address                          |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |                    Destination Address                        |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///     |                    Options                    |    Padding    |
///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///                     Example Internet Datagram Header
///                               Figure 4.
///
///  Note that each tick mark represents one bit position.
///
///
///
/// Internet Protocol version 4 (IPv4)
/// 
/// https://en.wikipedia.org/wiki/IPv4#Packet_structure
/// 
/// Min: 160 bits   Max: 256 bits
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Packet<'a, 'b> {
    version_ihl: u8,            //  4 bits, 4 bits
    /// Differentiated Services Code Point (DSCP) & Explicit Congestion Notification (ECN),
    /// Originally defined as the Type of service (ToS) field.
    dscp_ecn: u8,               //  6 bits, 2 bits
    /// This 16-bit field defines the entire packet size in bytes, including header and data. 
    /// The minimum size is 20 bytes (header without data) and the maximum is 65,535 bytes. 
    /// All hosts are required to be able to reassemble datagrams of size up to 576 bytes, 
    /// but most modern hosts handle much larger packets. 
    /// Sometimes links impose further restrictions on the packet size, 
    /// in which case datagrams must be fragmented. 
    /// Fragmentation in IPv4 is handled in either the host or in routers.
    total_length: u16,          // 16 bits
    identification: u16,        // 16 bits
    flags_fragment_offset: u16, //  3 bits, 13 bits
    time_to_live: u8,    //  8 bits
    protocol: u8,        //  8 bits
    header_checksum: u16,// 16 bits
    src_ip: u32,         // 32 bits
    dst_ip: u32,         // 32 bits
    options: Option<Options<'a>>, // 0 - 96 bits, start 160, end 256, if IHL >= 5
    payload: &'b [u8]
}

/// Internet Protocol version 6 (IPv6)
/// 
/// https://en.wikipedia.org/wiki/IPv6_packet
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv6Packet<'a> {
    version: u8,         //   4 bits
    traffic_class: u8,   //   8 bits
    flow_label: u32,     //  20 bits
    /// The size of the payload in octets, including any extension headers. 
    /// The length is set to zero when a Hop-by-Hop extension header carries a Jumbo Payload option.
    payload_length: u16, //  16 bits
    next_header: u8,     //   8 bits
    hoplimit: u8,        //   8 bits
    src_ip  : u128,      // 128 bits
    dst_ip  : u128,      // 128 bits
    payload : &'a [u8]
}

/// OSI Model Layer 4 
#[derive(Debug, PartialEq, Eq)]
pub enum Packet<'a, 'b> {
    V4(Ipv4Packet<'a, 'b>),
    V6(Ipv6Packet<'a>)
}


impl <'a, 'b>Ipv4Packet<'a, 'b> {
    #[allow(unused_variables)]
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        if payload.len() < Ipv4Packet::min_size() {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }

        let version_ihl = payload[0];
        let ihl = version_ihl & 0b_0000_1111;

        if (version_ihl >> 4) != 4 {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }

        let dscp_ecn    = payload[1];
        let total_length: u16   = BigEndian::read_u16(&payload[2..4]);
        let identification: u16 = BigEndian::read_u16(&payload[4..6]);
        let flags_fragment_offset: u16 = BigEndian::read_u16(&payload[6..8]);

        let time_to_live = payload[8];
        let protocol     = payload[9];
        let header_checksum: u16 = BigEndian::read_u16(&payload[10..12]);

        let src_ip: u32 = BigEndian::read_u32(&payload[12..16]);
        let dst_ip: u32 = BigEndian::read_u32(&payload[16..20]);

        let options: Option<Options<'a>>;
        let header_length: usize;
        if ihl >= 5 {
            if payload.len() < (Ipv4Packet::min_size() + 2) {
                return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
            }

            match Options::from_bytes(&payload[20..]) {
                Ok(ipv4_options) => {
                    let ip_v4_options_length = ipv4_options.len();
                    if payload.len() < (Ipv4Packet::min_size() + ip_v4_options_length) {    
                        return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
                    }
                    options = Some(ipv4_options);
                    header_length = 20 + ip_v4_options_length;
                }
                Err(e) => return Err(e)
            };
        } else {
            header_length = 20;
            options = None;
        }

        if payload.len() != total_length as usize {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }
        println!("Ipv4 Header length: {:?}", header_length);
        Ok(Ipv4Packet {
            version_ihl   : version_ihl,
            dscp_ecn      : dscp_ecn,
            total_length  : total_length,
            identification: identification,
            flags_fragment_offset: flags_fragment_offset,
            time_to_live  : time_to_live,
            protocol: protocol,
            header_checksum: header_checksum,
            src_ip: src_ip,
            dst_ip: dst_ip,
            options: options,
            payload: unsafe {transmute(&payload[header_length..])}
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }

    pub fn min_size() -> usize {
        20
    }

    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0b_0000_1111
    }
    pub fn dscp(&self) -> u8 {
        (self.dscp_ecn >> 2) as u8
    }
    pub fn ecn(&self) -> u8 {
        self.dscp_ecn & 0b_0000_0011
    }
    pub fn total_length(&self) -> u16 {
        self.total_length
    }
    pub fn flags(&self) -> u8 {
        (self.flags_fragment_offset >> 13) as u8
    }
    pub fn fragment_offset(&self) -> u16 {
        self.flags_fragment_offset & 0b_0001_1111
    }
    pub fn time_to_live(&self) -> u8 {
        self.time_to_live
    }
    /// [Protocol number](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
    /// of the header following the IPv4 header.
    pub fn protocol(&self) -> u8 {
        self.protocol
    }
    pub fn header_checksum(&self) -> u16 {
        self.header_checksum
    }
    pub fn src_ip(&self) -> u32 {
        self.src_ip
    }
    pub fn dst_ip(&self) -> u32 {
        self.dst_ip
    }
    pub fn options(&self) -> &'a Option<Options> {
        &self.options
    }
    pub fn payload(&self) -> &'b [u8] {
        self.payload
    }
    
    pub fn verify_checksum(&self) -> bool {
        unimplemented!();
    }
}

impl <'a>Ipv6Packet<'a> {
    #[allow(unused_variables)]
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        if payload.len() < 40 {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }
        
        let version       = payload[0] >> 4;
        
        if version != 6 {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "ipv6 packet version != 6 !"));
        }
        
        let traffic_class = (payload[0] & 0b_0000_1111) | (payload[1] >> 4);
        let flow_label    = (((payload[1] & 0b_0000_1111) as u32) << 16) | ((payload[2] as u32) << 8) | (payload[3] as u32);
        let payload_length: u16 = BigEndian::read_u16(&payload[4..6]);

        if payload.len() != payload_length as usize {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }
        
        let next_header = payload[6];
        let hoplimit    = payload[7];
        
        let src_ip6 = ::std::net::Ipv6Addr::new(
            BigEndian::read_u16(&payload[ 8..10]), BigEndian::read_u16(&payload[10..12]), BigEndian::read_u16(&payload[12..14]),
            BigEndian::read_u16(&payload[14..16]), BigEndian::read_u16(&payload[16..18]), BigEndian::read_u16(&payload[18..20]),
            BigEndian::read_u16(&payload[20..22]), BigEndian::read_u16(&payload[22..24])
        );
        let src_ip: u128 = u128::from(src_ip6);

        let dst_ip6 = ::std::net::Ipv6Addr::new(
            BigEndian::read_u16(&payload[24..26]), BigEndian::read_u16(&payload[26..28]), BigEndian::read_u16(&payload[28..30]),
            BigEndian::read_u16(&payload[30..32]), BigEndian::read_u16(&payload[32..34]), BigEndian::read_u16(&payload[34..36]),
            BigEndian::read_u16(&payload[36..38]), BigEndian::read_u16(&payload[38..40])
        );
        let dst_ip: u128 = u128::from(dst_ip6);

        Ok(Ipv6Packet {
            version: version,
            traffic_class: traffic_class,
            flow_label: flow_label,
            payload_length: payload_length,
            next_header: next_header,
            hoplimit: hoplimit,
            src_ip: src_ip,
            dst_ip: dst_ip,
            payload: unsafe { transmute(&payload[40..]) }
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }

    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn traffic_class(&self) -> u8 {
        self.traffic_class
    }
    pub fn flow_label(&self) -> u32 {
        self.flow_label
    }
    pub fn payload_length(&self) -> u16 {
        self.payload_length
    }
    pub fn next_header(&self) -> u8 {
        self.next_header
    }
    pub fn hoplimit(&self) -> u8 {
        self.hoplimit
    }
    pub fn src_ip(&self) -> u128 {
        self.src_ip
    }
    pub fn dst_ip(&self) -> u128 {
        self.dst_ip
    }
    pub fn payload(&self) -> &'a [u8] {
        &self.payload
    }
    
    pub fn verify_checksum(&self) -> bool {
        unimplemented!();
    }
}

impl <'a, 'b>Packet<'a, 'b> {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        // let ver = u8::from_str_radix(&format!("{:08b}", payload[0])[0..4], 2).unwrap();
        let ver = payload[0] >> 4;
        match ver {
            // TODO: TCP/IP/ICMPv6 checksum
            4u8 => match Ipv4Packet::from_bytes(payload) {
                Ok(packet) => Ok(Packet::V4(packet)),
                Err(e)     => Err(e)
            },
            6u8 => match Ipv6Packet::from_bytes(payload) {
                Ok(packet) => Ok(Packet::V6(packet)),
                Err(e)     => Err(e)
            },
            version @ _ => {
                println!("RawPacket: {:?}", payload);
                println!("IP Version: {:?}", version);
                Err(::std::io::Error::new(::std::io::ErrorKind::Other, "IP Version Error!"))
            }
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        match *self {
            Packet::V4(ref packet) => packet.as_bytes(),
            Packet::V6(ref packet) => packet.as_bytes()
        }
    }

    pub fn payload(&self) -> &[u8] {
        match *self {
            Packet::V4(ref packet) => packet.payload(),
            Packet::V6(ref packet) => packet.payload()
        }
    }
    
    pub fn tcp_ip_checksum(&self) -> bool {
        // https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation
        #[derive(Debug, PartialEq, Eq)]
        pub struct TcpIpv4PseudoHeader{
            src_ip  : u32,
            dst_ip  : u32,
            zeroes  : u8,
            protocol: u8,
            tcp_length: u16,
            // TCP Packet
            // ...
        }

        #[derive(Debug, PartialEq, Eq)]
        pub struct TcpIpv6PseudoHeader{
            src_ip     : u128,
            dst_ip     : u128,
            tcp_length : u32,
            zeroes     : u32,   // 24 bits
            next_header: u8,
            // TCP Packet
            // ...
        }
        unimplemented!();
    }
    pub fn udp_ip_checksum(&self) -> bool {
        // https://en.wikipedia.org/wiki/User_Datagram_Protocol#Checksum_computation
        #[derive(Debug, PartialEq, Eq)]
        pub struct UdpIpv4PseudoHeader{
            src_ip  : u32,
            dst_ip  : u32,
            zeroes  : u8,
            protocol: u8,
            udp_length: u16,
            // UDP Packet
            // ...
        }

        #[derive(Debug, PartialEq, Eq)]
        pub struct UdpIpv6PseudoHeader{
            src_ip     : u128,
            dst_ip     : u128,
            udp_length : u32,
            zeroes     : u32,   // 24 bits
            next_header: u8,
            // UDP Packet
            // ...
        }
        unimplemented!();
    }
    /// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_version_6#Message_checksum
    pub fn icmp_ip_checksum(&self) -> bool {
        #[derive(Debug, PartialEq, Eq)]
        pub struct IcmpIpv6PseudoHeader {
            src_ip        : u128,
            dst_ip        : u128,
            icmp_v6_length: u32,
            zeros         : u16,
            next_header   : u16
        }
        unimplemented!();
    }
}