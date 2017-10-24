
use byteorder::{BigEndian, ReadBytesExt};

use std::mem::transmute;

/**
DSCP ECN:
      Bits 0-2:  Precedence.
      Bit    3:  0 = Normal Delay,      1 = Low Delay.
      Bits   4:  0 = Normal Throughput, 1 = High Throughput.
      Bits   5:  0 = Normal Relibility, 1 = High Relibility.
      Bit  6-7:  Reserved for Future Use.

         0     1     2     3     4     5     6     7
      +-----+-----+-----+-----+-----+-----+-----+-----+
      |                 |     |     |     |     |     |
      |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
      |                 |     |     |     |     |     |
      +-----+-----+-----+-----+-----+-----+-----+-----+

        Precedence

          111 - Network Control
          110 - Internetwork Control
          101 - CRITIC/ECP
          100 - Flash Override
          011 - Flash
          010 - Immediate
          001 - Priority
          000 - Routine
**/

#[derive(Debug, PartialEq, Eq)]
pub enum Delay {
    Normal,
    Low
}
#[derive(Debug, PartialEq, Eq)]
pub enum Throughput {
    Normal,
    High
}
#[derive(Debug, PartialEq, Eq)]
pub enum Relibility {
    Normal,
    High
}
impl Delay {
    pub fn to_u8(&self) -> u8 {
        match *self {
            Delay::Normal => 0,
            Delay::Low => 1,
        }
    }
}
impl Throughput {
    pub fn to_u8(&self) -> u8 {
        match *self {
            Throughput::Normal => 0,
            Throughput::High => 1,
        }
    }
}
impl Relibility {
    pub fn to_u8(&self) -> u8 {
        match *self {
            Relibility::Normal => 0,
            Relibility::High => 1,
        }
    }
}

/// Precedence
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq)]
pub enum ServiceKind {
    NetworkControl(Delay, Throughput, Relibility),
    InternetworkControl(Delay, Throughput, Relibility),
    CRITIC_ECP(Delay, Throughput, Relibility),
    FlashOverride(Delay, Throughput, Relibility),
    Flash(Delay, Throughput, Relibility),
    Immediate(Delay, Throughput, Relibility),
    Priority(Delay, Throughput, Relibility),
    Routine(Delay, Throughput, Relibility)
}

impl ServiceKind {
    pub fn to_u8(&self) -> u8 {
        match *self {
            ServiceKind::NetworkControl(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b111_000_00,
            ServiceKind::NetworkControl(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b111_001_00,
            ServiceKind::NetworkControl(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b111_010_00,
            ServiceKind::NetworkControl(Delay::Normal, Throughput::High, Relibility::High)     => 0b111_011_00,
            ServiceKind::NetworkControl(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b111_100_00,
            ServiceKind::NetworkControl(Delay::Low, Throughput::Normal, Relibility::High)      => 0b111_101_00,
            ServiceKind::NetworkControl(Delay::Low, Throughput::High, Relibility::Normal)      => 0b111_110_00,
            ServiceKind::NetworkControl(Delay::Low, Throughput::High, Relibility::High)        => 0b111_111_00,

            ServiceKind::InternetworkControl(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b110_000_00,
            ServiceKind::InternetworkControl(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b110_001_00,
            ServiceKind::InternetworkControl(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b110_010_00,
            ServiceKind::InternetworkControl(Delay::Normal, Throughput::High, Relibility::High)     => 0b110_011_00,
            ServiceKind::InternetworkControl(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b110_100_00,
            ServiceKind::InternetworkControl(Delay::Low, Throughput::Normal, Relibility::High)      => 0b110_101_00,
            ServiceKind::InternetworkControl(Delay::Low, Throughput::High, Relibility::Normal)      => 0b110_110_00,
            ServiceKind::InternetworkControl(Delay::Low, Throughput::High, Relibility::High)        => 0b110_111_00,
            
            ServiceKind::CRITIC_ECP(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b101_000_00,
            ServiceKind::CRITIC_ECP(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b101_001_00,
            ServiceKind::CRITIC_ECP(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b101_010_00,
            ServiceKind::CRITIC_ECP(Delay::Normal, Throughput::High, Relibility::High)     => 0b101_011_00,
            ServiceKind::CRITIC_ECP(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b101_100_00,
            ServiceKind::CRITIC_ECP(Delay::Low, Throughput::Normal, Relibility::High)      => 0b101_101_00,
            ServiceKind::CRITIC_ECP(Delay::Low, Throughput::High, Relibility::Normal)      => 0b101_110_00,
            ServiceKind::CRITIC_ECP(Delay::Low, Throughput::High, Relibility::High)        => 0b101_111_00,

            ServiceKind::FlashOverride(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b100_000_00,
            ServiceKind::FlashOverride(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b100_001_00,
            ServiceKind::FlashOverride(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b100_010_00,
            ServiceKind::FlashOverride(Delay::Normal, Throughput::High, Relibility::High)     => 0b100_011_00,
            ServiceKind::FlashOverride(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b100_100_00,
            ServiceKind::FlashOverride(Delay::Low, Throughput::Normal, Relibility::High)      => 0b100_101_00,
            ServiceKind::FlashOverride(Delay::Low, Throughput::High, Relibility::Normal)      => 0b100_110_00,
            ServiceKind::FlashOverride(Delay::Low, Throughput::High, Relibility::High)        => 0b100_111_00,

            ServiceKind::Flash(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b011_000_00,
            ServiceKind::Flash(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b011_001_00,
            ServiceKind::Flash(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b011_010_00,
            ServiceKind::Flash(Delay::Normal, Throughput::High, Relibility::High)     => 0b011_011_00,
            ServiceKind::Flash(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b011_100_00,
            ServiceKind::Flash(Delay::Low, Throughput::Normal, Relibility::High)      => 0b011_101_00,
            ServiceKind::Flash(Delay::Low, Throughput::High, Relibility::Normal)      => 0b011_110_00,
            ServiceKind::Flash(Delay::Low, Throughput::High, Relibility::High)        => 0b011_111_00,

            ServiceKind::Immediate(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b010_000_00,
            ServiceKind::Immediate(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b010_001_00,
            ServiceKind::Immediate(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b010_010_00,
            ServiceKind::Immediate(Delay::Normal, Throughput::High, Relibility::High)     => 0b010_011_00,
            ServiceKind::Immediate(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b010_100_00,
            ServiceKind::Immediate(Delay::Low, Throughput::Normal, Relibility::High)      => 0b010_101_00,
            ServiceKind::Immediate(Delay::Low, Throughput::High, Relibility::Normal)      => 0b010_110_00,
            ServiceKind::Immediate(Delay::Low, Throughput::High, Relibility::High)        => 0b010_111_00,

            ServiceKind::Priority(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b001_000_00,
            ServiceKind::Priority(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b001_001_00,
            ServiceKind::Priority(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b001_010_00,
            ServiceKind::Priority(Delay::Normal, Throughput::High, Relibility::High)     => 0b001_011_00,
            ServiceKind::Priority(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b001_100_00,
            ServiceKind::Priority(Delay::Low, Throughput::Normal, Relibility::High)      => 0b001_101_00,
            ServiceKind::Priority(Delay::Low, Throughput::High, Relibility::Normal)      => 0b001_110_00,
            ServiceKind::Priority(Delay::Low, Throughput::High, Relibility::High)        => 0b001_111_00,

            ServiceKind::Routine(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b000_000_00,
            ServiceKind::Routine(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b000_001_00,
            ServiceKind::Routine(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b000_010_00,
            ServiceKind::Routine(Delay::Normal, Throughput::High, Relibility::High)     => 0b000_011_00,
            ServiceKind::Routine(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b000_100_00,
            ServiceKind::Routine(Delay::Low, Throughput::Normal, Relibility::High)      => 0b000_101_00,
            ServiceKind::Routine(Delay::Low, Throughput::High, Relibility::Normal)      => 0b000_110_00,
            ServiceKind::Routine(Delay::Low, Throughput::High, Relibility::High)        => 0b000_111_00
        }
    }
}


/// IPv4 OPTION NUMBERS
/// 
/// https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ip-parameters-1
///
/// Format:
/// 
///     copy  : 1  bits
///     class : 2  bits
///     number: 5  bits
///     value : 8  bits
///     data  : .. bits
/// 
/// Option Fields: copied(copy), class, number, value(length)
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Option<'a> {
    ccn  : u8,              // 8 bits , Fields: copied(copy), class, number
    value: u8,              // 8 bits
    data : Option<&'a [u8]> // Option-specific data. This field may not exist for simple options.
}

impl <'a>Ipv4Option<'a> {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        if payload.len() < 2 {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }

        let ccn   = payload[0];
        let value = (payload[1] + (8 - (payload[1] % 8))) / 8;  // in bytes
        
        if payload.len() < (2 + value) as usize {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }

        let data: Option<&'a [u8]>;
        if value > 0 {
            data = Some(unsafe { transmute(&payload[2..(2+value as usize)]) });
        } else {
            data = None
        }

        Ok(Ipv4Option {
            ccn  : ccn,
            value: value,
            data : data
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(self.len());
        bytes.push(self.ccn);
        bytes.push(self.value);
        if self.data.is_some(){
            bytes.extend_from_slice(self.data.unwrap())
        }
        bytes
    }
    
    pub fn ccn(&self) -> u8 {
        // copied(copy), class, number
        self.ccn
    }

    pub fn value(&self) -> u8 {
        // value(length)
        self.value
    }

    pub fn length(&self) -> u8 {
        self.value()
    }
    pub fn len(&self) -> usize {
        self.length() as usize + 2
    }

    pub fn data(&self) -> Option<&'a [u8]> {
        self.data
    }

    pub fn copied(&self) -> u8 {
        self.ccn >> 7
    }

    pub fn class(&self) -> u8 {
        (self.ccn >> 5) & 0b011
    }

    pub fn number(&self) -> u8 {
        self.ccn & 0b_0001_1111
    }



    /// copied(0) class(0) number(0) value(0)    End of Options List, [RFC791][Jon_Postel]
    pub fn is_eool(&self) -> bool {
        self.ccn == 0 && self.value == 0
    }
    /// copied(0) class(0) number(1) value(1)    No Operation, [RFC791][Jon_Postel]
    pub fn is_nop(&self) -> bool {
        self.ccn == 1 && self.value == 1
    }
    /// copied(1) class(0) number(2) value(130)    Security, [RFC1108]
    pub fn is_sec(&self) -> bool {
        self.ccn == 130 && self.value == 130
    }
    /// copied(1) class(0) number(3) value(131)    Loose Source Route, [RFC791][Jon_Postel]
    pub fn is_lsr(&self) -> bool {
        self.ccn == 131 && self.value == 131
    }
    /// copied(0) class(2) number(4) value(68)    Time Stamp, [RFC791][Jon_Postel]
    pub fn is_ts(&self) -> bool {
        self.ccn == 68 && self.value == 68
    }
    /// copied(1) class(0) number(5) value(133)    Extended Security, [RFC1108]
    pub fn is_e_sec(&self) -> bool {
        self.ccn == 133 && self.value == 133
    }
    /// copied(1) class(0) number(6) value(134)    Commercial Security, [draft-ietf-cipso-ipsecurity-01]
    pub fn is_cipso(&self) -> bool {
        self.ccn == 134 && self.value == 134
    }
    /// copied(0) class(0) number(7) value(7)    Record Route, [RFC791][Jon_Postel]
    pub fn is_rr(&self) -> bool {
        self.ccn == 7 && self.value == 7
    }
    /// copied(1) class(0) number(8) value(136)    Stream ID, [RFC791][Jon_Postel][RFC6814][1]
    pub fn is_sid(&self) -> bool {
        self.ccn == 136 && self.value == 136
    }
    /// copied(1) class(0) number(9) value(137)    Strict Source Route, [RFC791][Jon_Postel]
    pub fn is_ssr(&self) -> bool {
        self.ccn == 137 && self.value == 137
    }
    /// copied(0) class(0) number(10) value(10)    Experimental Measurement, [ZSu]
    pub fn is_zsu(&self) -> bool {
        self.ccn == 10 && self.value == 10
    }
    /// copied(0) class(0) number(11) value(11)    MTU Probe, [RFC1063][RFC1191][1]
    pub fn is_mtup(&self) -> bool {
        self.ccn == 11 && self.value == 11
    }
    /// copied(0) class(0) number(12) value(12)    MTU Reply, [RFC1063][RFC1191][1]
    pub fn is_mtur(&self) -> bool {
        self.ccn == 12 && self.value == 12
    }
    /// copied(1) class(2) number(13) value(205)    Experimental Flow Control, [Greg_Finn]
    pub fn is_finn(&self) -> bool {
        self.ccn == 205 && self.value == 205
    }
    /// copied(1) class(0) number(14) value(142)    Experimental Access Control, [Deborah_Estrin][RFC6814][1]
    pub fn is_visa(&self) -> bool {
        self.ccn == 142 && self.value == 142
    }
    /// copied(0) class(0) number(15) value(15)    ???, [VerSteeg][RFC6814][1]
    pub fn is_encode(&self) -> bool {
        self.ccn == 15 && self.value == 15
    }
    /// copied(1) class(0) number(16) value(144)    IMI Traffic Descriptor, [Lee]
    pub fn is_imitd(&self) -> bool {
        self.ccn == 144 && self.value == 144
    }
    /// copied(1) class(0) number(17) value(145)    Extended Internet Protocol, [RFC1385][RFC6814][1]
    pub fn is_eip(&self) -> bool {
        self.ccn == 145 && self.value == 145
    }
    /// copied(0) class(2) number(18) value(82)    Traceroute, [RFC1393][RFC6814][1]
    pub fn is_tr(&self) -> bool {
        self.ccn == 82 && self.value == 82
    }
    /// copied(1) class(0) number(19) value(147)    Address Extension, [Ullmann IPv7][RFC6814][1]
    pub fn is_addext(&self) -> bool {
        self.ccn == 147 && self.value == 147
    }
    /// copied(1) class(0) number(20) value(148)    Router Alert, [RFC2113]
    pub fn is_rtralt(&self) -> bool {
        self.ccn == 148 && self.value == 148
    }
    /// copied(1) class(0) number(21) value(149)    Selective Directed Broadcast, [Charles_Bud_Graff][RFC6814][1]
    pub fn is_sdb(&self) -> bool {
        self.ccn == 149 && self.value == 149
    }
    /// copied(1) class(0) number(23) value(151)    Dynamic Packet State, [Andy_Malis][RFC6814][1]
    pub fn is_dps(&self) -> bool {
        self.ccn == 151 && self.value == 151
    }
    /// copied(1) class(0) number(24) value(152)    Upstream Multicast Pkt., [Dino_Farinacci][RFC6814][1]
    pub fn is_ump(&self) -> bool {
        self.ccn == 152 && self.value == 152
    }
    /// copied(0) class(0) number(25) value(25)    Quick-Start, [RFC4782]
    pub fn is_qs(&self) -> bool {
        self.ccn == 25 && self.value == 25
    }
    /// copied(0) class(0) number(30) value(30)    RFC3692-style Experiment [2], [RFC4727]
    pub fn is_exp1(&self) -> bool {
        self.ccn == 30 && self.value == 30
    }
    /// copied(0) class(2) number(30) value(94)    RFC3692-style Experiment [2], [RFC4727]
    pub fn is_exp2(&self) -> bool {
        self.ccn == 94 && self.value == 94
    }
    /// copied(1) class(0) number(30) value(158)    RFC3692-style Experiment [2], [RFC4727]
    pub fn is_exp3(&self) -> bool {
        self.ccn == 158 && self.value == 158
    }
    /// copied(1) class(2) number(30) value(222)    RFC3692-style Experiment [2], [RFC4727]
    pub fn is_exp4(&self) -> bool {
        self.ccn == 222 && self.value == 222
    }

}


/// Internet Protocol version 4 (IPv4)
/// 
/// https://en.wikipedia.org/wiki/IPv4#Packet_structure
/// 
/// Min: 160 bits   Max: 256 bits
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Packet<'a, 'b> {
    version_ihl: u8,            //  4 bits, 4 bits
    dscp_ecn: u8,               //  6 bits, 2 bits
    total_length: u16,          // 16 bits
    identification: u16,        // 16 bits
    flags_fragment_offset: u16, //  3 bits, 13 bits
    time_to_live: u8,    //  8 bits
    protocol: u8,        //  8 bits
    header_checksum: u16,// 16 bits
    src_ip: u32,         // 32 bits
    dst_ip: u32,         // 32 bits
    options: Option<Ipv4Option<'a>>, // 0 - 96 bits, start 160, end 256, if IHL >= 5
    payload: &'b [u8]
}

/// Internet Protocol version 6 (IPv6)
/// 
/// https://en.wikipedia.org/wiki/IPv6_packet
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv6Packet<'a> {
    version: u8,         //  4 bits
    traffic_class: u8,   //  8 bits
    flow_label: u32,     // 20 bits
    payload_length: u16, // 16 bits
    next_header: u8,     //  8 bits
    hoplimit: u8,        //  8 bits
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

        if (version_ihl >> 4) != 4 {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }
        let ihl = u8::from_str_radix(&format!("{:08b}", version_ihl)[4..8], 2).unwrap();

        let dscp_ecn    = payload[1];

        let mut total_length_bytes = &payload[2..4];
        let total_length: u16          = total_length_bytes.read_u16::<BigEndian>().unwrap();
        let mut identification_bytes = &payload[4..6];
        let identification: u16        = identification_bytes.read_u16::<BigEndian>().unwrap();

        let mut flags_fragment_offset_bytes = &payload[6..8];
        let flags_fragment_offset: u16 = flags_fragment_offset_bytes.read_u16::<BigEndian>().unwrap();

        let time_to_live = payload[8];
        let protocol     = payload[9];

        let mut header_checksum = &payload[10..12];
        let header_checksum: u16 = header_checksum.read_u16::<BigEndian>().unwrap();

        let mut src_ip_bytes = &[payload[12], payload[13], payload[14], payload[15]][..];
        let src_ip: u32 = src_ip_bytes.read_u32::<BigEndian>().unwrap();
        let mut dst_ip_bytes = &[payload[16], payload[17], payload[18], payload[19]][..];
        let dst_ip: u32 = dst_ip_bytes.read_u32::<BigEndian>().unwrap();
        
        let options: Option<Ipv4Option<'a>>;
        let header_length: usize;
        if ihl >= 5 {
            if payload.len() < (Ipv4Packet::min_size() + 2) {
                return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
            }

            match Ipv4Option::from_bytes(&payload[20..]) {
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
        u8::from_str_radix(&format!("{:08b}", self.version_ihl)[4..8], 2).unwrap()
    }
    pub fn dscp(&self) -> u8 {
        u8::from_str_radix(&format!("{:08b}", self.dscp_ecn)[0..6], 2).unwrap()
    }
    pub fn ecn(&self) -> u8 {
        u8::from_str_radix(&format!("{:08b}", self.dscp_ecn)[6..8], 2).unwrap()
    }
    pub fn total_length(&self) -> u16 {
        self.total_length
    }
    pub fn flags(&self) -> u8 {
        u8::from_str_radix(&format!("{:016b}", self.flags_fragment_offset)[0..3], 2).unwrap()
    }
    pub fn fragment_offset(&self) -> u16 {
        u16::from_str_radix(&format!("{:016b}", self.flags_fragment_offset)[3..16], 2).unwrap()
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
    pub fn options(&self) -> &'a Option<Ipv4Option> {
        &self.options
    }
    pub fn payload(&self) -> &'b [u8] {
        self.payload
    }
    
    pub fn verifying(&self) -> bool {
        unimplemented!();
    }
}


impl <'a>Ipv6Packet<'a> {
    #[allow(unused_variables)]
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        println!("[WARN] 检测到不支持的 IPv6 Packet: {:?}", payload);
        unimplemented!();
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
    pub fn payload(&self) -> &'a [u8] {
        &self.payload
    }

    pub fn verifying(&self) -> bool {
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