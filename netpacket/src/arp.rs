
use byteorder::{BigEndian, ByteOrder};
use std::mem::transmute;

/// Address Resolution Protocol (ARP)
/// 
/// Spec:
/// 
/// *   https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure
/// *   https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
/// 
/// *NOTE:*
/// 
///     In Internet Protocol Version 6 (IPv6) networks, 
///     the functionality of ARP is provided by the Neighbor Discovery Protocol (NDP).
/// 
/// Packet size : https://supportforums.cisco.com/t5/lan-switching-and-routing/arp-packet-size/td-p/1551467
#[derive(Debug, PartialEq, Eq)]
pub struct Packet {
    hardware_type: u16,               // 16 bits
    protocol_type: u16,               // 16 bits , EtherType (These numbers share the Ethertype space. See: <http://www.iana.org/assignments/ethernet-numbers>)
    hardware_address_length: u8,      //  8 bits
    protocol_address_length: u8,      //  8 bits
    operation: u16,                   // 16 bits
    sender_hardware_address: [u8; 6], // 48 bits , MacAddr
    sender_protocol_address: u32,     // 32 bits , Ipv4Addr
    target_hardware_address: [u8; 6], // 48 bits , MacAddr
    target_protocol_address: u32      // 32 bits , Ipv4Addr
}

/// Operation Codes
/// 
/// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-1
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq)]
pub enum Operation {
    /// 1   REQUEST     [RFC826][RFC5227]
    Request,
    /// 2   REPLY   [RFC826][RFC5227]
    Reply,
    /// 3   request Reverse     [RFC903]
    RequestReverse,
    /// 4   reply Reverse   [RFC903]
    ReplyReverse,
    /// 5   DRARP-Request   [RFC1931]
    DrarpRequest,
    /// 6   DRARP-Reply     [RFC1931]
    DrarpReply,
    /// 7   DRARP-Error     [RFC1931]
    DrarpError,
    /// 8   InARP-Request   [RFC2390]
    InarpRequest,
    /// 9   InARP-Reply     [RFC2390]
    InarpReply,
    /// 10  ARP-NAK     [RFC1577]
    ArpNak,
    /// 11  MARS-Request    [Grenville_Armitage]
    MarsRequest,
    /// 12  MARS-Multi  [Grenville_Armitage]
    MarsMulti,
    /// 13  MARS-MServ  [Grenville_Armitage]
    MarsMServ,
    /// 14  MARS-Join   [Grenville_Armitage]
    MarsJoin,
    /// 15  MARS-Leave  [Grenville_Armitage]
    MarsLeave,
    /// 16  MARS-NAK    [Grenville_Armitage]
    MarsNAK,
    /// 17  MARS-Unserv     [Grenville_Armitage]
    MarsUnserv,
    /// 18  MARS-SJoin  [Grenville_Armitage]
    MarsSJoin,
    /// 19  MARS-SLeave     [Grenville_Armitage]
    MarsSLeave,
    /// 20  MARS-Grouplist-Request  [Grenville_Armitage]
    MarsGrouplistRequest,
    /// 21  MARS-Grouplist-Reply    [Grenville_Armitage]
    MarsGrouplistReply,
    /// 22  MARS-Redirect-Map   [Grenville_Armitage]
    MarsRedirectMap,
    /// 23  MAPOS-UNARP     [Mitsuru_Maruyama][RFC2176]
    MaposUNARP,
    /// 24  OP_EXP1     [RFC5494]
    OpExp1,
    /// 25  OP_EXP2     [RFC5494]
    OpExp2,
    Unknow(u16)
}

/// Hardware Types
/// 
///     Range                                       Registration Procedures      Note 
///     ------------------------------------------  -----------------------     -------
///     requests for values below 256                    Expert Review   
///     requests for more than one value                 Expert Review   
///     requests for one value greater than 255       First Come First Served     
///     requests for one value, no value specified    First Come First Served     can only be assigned a two-octet value (i.e., a value greater than 255)
/// 
/// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-1
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq)]
pub enum HardwareType {
    /// 1   Ethernet (10Mb)     [Jon_Postel]
    Ethernet,
    /// 2   Experimental Ethernet (3Mb)     [Jon_Postel]
    ExperimentalEthernet,
    /// 6   IEEE 802 Networks   [Jon_Postel]
    IEEE802Networks,
    /// 11  LocalTalk   [Joyce_K_Reynolds]
    LocalTalk,
    /// 12  LocalNet (IBM PCNet or SYTEK LocalNET)  [Joseph Murdock]
    LocalNet,
    /// 13  Ultra link  [Rajiv_Dhingra]
    UltraLink,
    /// 15  Frame Relay     [Andy_Malis]
    FrameRelay,
    /// 18  Fibre Channel   [RFC4338]
    FibreChannel,
    /// 20  Serial Line     [Jon_Postel]
    SerialLine,
    /// 24  IEEE 1394.1995  [Myron_Hattig]
    IEEE1394_1995,
    /// 29  IP and ARP over ISO 7816-3  [Scott_Guthery]
    IPAndARPOverISO7816_3,
    /// 30  ARPSec  [Jerome_Etienne]
    ARPSec,
    /// 31  IPsec tunnel    [RFC3456]
    IPsecTunnel,
    /// 32  InfiniBand (TM)     [RFC4391]
    InfiniBand,
    /// 35  Pure IP     [Inaky_Perez-Gonzalez]
    PureIP,
    /// 257 AEthernet   [Geoffroy_Gramaize]
    AEthernet,
    Unknow(u16)
}


impl Packet {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        if payload.len() < 28 {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }
        let hardware_type: u16 = BigEndian::read_u16(&payload[0..2]);
        let protocol_type: u16 = BigEndian::read_u16(&payload[2..4]);
        let hardware_address_length = payload[4];
        let protocol_address_length = payload[5];
        let operation: u16 = BigEndian::read_u16(&payload[6..8]);
        let sender_hardware_address: [u8; 6] = [payload[8], payload[9], payload[10], payload[11], payload[12], payload[13]];
        let sender_protocol_address: u32 = BigEndian::read_u32(&payload[14..18]);
        
        let target_hardware_address: [u8; 6] = [payload[18], payload[19], payload[20], payload[21], payload[22], payload[23]];
        let target_protocol_address: u32 = BigEndian::read_u32(&payload[24..28]);
        Ok(Packet {
            hardware_type: hardware_type,
            protocol_type: protocol_type,
            hardware_address_length: hardware_address_length,
            protocol_address_length: protocol_address_length,
            operation: operation,
            sender_hardware_address: sender_hardware_address,
            sender_protocol_address: sender_protocol_address,
            target_hardware_address: target_hardware_address,
            target_protocol_address: target_protocol_address
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(28);
        
        bytes.push( (self.hardware_type >> 8) as u8 );
        bytes.push( (self.hardware_type & 0xff) as u8 );

        bytes.push( (self.protocol_type >> 8) as u8 );
        bytes.push( (self.protocol_type & 0xff) as u8 );

        bytes.push(self.hardware_address_length);
        bytes.push(self.protocol_address_length);

        bytes.push( (self.operation >> 8) as u8 );
        bytes.push( (self.operation & 0xff) as u8 );

        bytes.extend_from_slice(&self.sender_hardware_address);
        
        let sender_protocol_address_bytes: [u8; 4] = unsafe { transmute(self.sender_protocol_address.to_be()) };
        bytes.extend_from_slice(&sender_protocol_address_bytes);
        

        bytes.extend_from_slice(&self.target_hardware_address);
        let target_protocol_address_bytes: [u8; 4] = unsafe { transmute(self.target_protocol_address.to_be()) };
        bytes.extend_from_slice(&target_protocol_address_bytes);
        
        bytes
    }

    pub fn hardware_type(&self) -> u16 {
        self.hardware_type
    }
    pub fn protocol_type(&self) -> u16 {
        self.protocol_type
    }
    pub fn hardware_address_length(&self) -> u8 {
        self.hardware_address_length
    }
    pub fn protocol_address_length(&self) -> u8 {
        self.protocol_address_length
    }
    pub fn operation(&self) -> u16 {
        self.operation
    }
    pub fn sender_hardware_address(&self) -> [u8; 6] {
        self.sender_hardware_address
    }
    pub fn sender_protocol_address(&self) -> u32 {
        self.sender_protocol_address
    }
    pub fn target_hardware_address(&self) -> [u8; 6] {
        self.target_hardware_address
    }
    pub fn target_protocol_address(&self) -> u32 {
        self.target_protocol_address
    }
}


impl Operation {
    pub fn from_u16(n: u16) -> Result<Self, ::std::io::Error> {
        use self::Operation::*;
        match n {
            0 | 26 ... 65534 | 65535 => Ok(Unknow(n)),
            1 => Ok(Request),
            2 => Ok(Reply),
            3 => Ok(RequestReverse),
            4 => Ok(ReplyReverse),
            5 => Ok(DrarpRequest),
            6 => Ok(DrarpReply),
            7 => Ok(DrarpError),
            8 => Ok(InarpRequest),
            9 => Ok(InarpReply),
            10 => Ok(ArpNak),
            11 => Ok(MarsRequest),
            12 => Ok(MarsMulti),
            13 => Ok(MarsMServ),
            14 => Ok(MarsJoin),
            15 => Ok(MarsLeave),
            16 => Ok(MarsNAK),
            17 => Ok(MarsUnserv),
            18 => Ok(MarsSJoin),
            19 => Ok(MarsSLeave),
            20 => Ok(MarsGrouplistRequest),
            21 => Ok(MarsGrouplistReply),
            22 => Ok(MarsRedirectMap),
            23 => Ok(MaposUNARP),
            24 => Ok(OpExp1),
            25 => Ok(OpExp2),
            _ => unreachable!()
        }
    }

    pub fn to_u16(&self) -> u16 {
        use self::Operation::*;
        match *self {
            Request => 1,
            Reply   => 2,
            RequestReverse => 3,
            ReplyReverse   => 4,
            DrarpRequest => 5,
            DrarpReply => 6,
            DrarpError => 7,
            InarpRequest => 8,
            InarpReply => 9,
            ArpNak => 10,
            MarsRequest => 11,
            MarsMulti => 12,
            MarsMServ => 13,
            MarsJoin => 14,
            MarsLeave => 15,
            MarsNAK => 16,
            MarsUnserv => 17,
            MarsSJoin => 18,
            MarsSLeave => 19,
            MarsGrouplistRequest => 20,
            MarsGrouplistReply => 21,
            MarsRedirectMap => 22,
            MaposUNARP => 23,
            OpExp1 => 24,
            OpExp2 => 25,
            Unknow(n) => n
        }
    }

    pub fn is_assigned(&self) -> bool {
        match self.to_u16(){
            1 ... 25 => true,
            _ => false
        }
    }

    pub fn is_unassigned(&self) -> bool {
        match self.to_u16(){
            0 | 26 ... 65534 | 65535 => true,
            _ => false
        }
    }

    pub fn is_reserved(&self) -> bool {
        match self.to_u16(){
            0 | 65535 => true,
            _ => false
        }
    }

}

impl HardwareType {
    pub fn from_u16(n: u16) -> Result<Self, ::std::io::Error> {
        use self::HardwareType::*;
        match n {
            1 => Ok(Ethernet),
            2 => Ok(ExperimentalEthernet),
            6 => Ok(IEEE802Networks),
            11 => Ok(LocalTalk),
            12 => Ok(LocalNet),
            13 => Ok(UltraLink),
            15 => Ok(FrameRelay),
            18 => Ok(FibreChannel),
            20 => Ok(SerialLine),
            24 => Ok(IEEE1394_1995),
            29 => Ok(IPAndARPOverISO7816_3),
            30 => Ok(ARPSec),
            31 => Ok(IPsecTunnel),
            32 => Ok(InfiniBand),
            35 => Ok(PureIP),
            257 => Ok(AEthernet),
            0 | 38...255 | 258...65534 | 65535 => Ok(Unknow(n)),
            _ => unreachable!()
        }
    }

    pub fn to_u16(&self) -> u16 {
        use self::HardwareType::*;
        match *self {
            Ethernet => 1,
            ExperimentalEthernet => 2,
            IEEE802Networks => 6,
            LocalTalk => 11,
            LocalNet  => 12,
            UltraLink => 13,
            FrameRelay=> 15,
            FibreChannel => 18,
            SerialLine => 20,
            IEEE1394_1995 => 24,
            IPAndARPOverISO7816_3 => 29,
            ARPSec => 30,
            IPsecTunnel => 31,
            InfiniBand => 32,
            PureIP => 35,
            AEthernet => 257,
            Unknow(n) => n

        }
    }

    pub fn is_assigned(&self) -> bool {
        match self.to_u16(){
            1 ... 37 | 256 | 257 => true,
            _ => false
        }
    }

    pub fn is_unassigned(&self) -> bool {
        match self.to_u16(){
            0 | 38 ... 255 | 258 ... 65534 | 65535 => true,
            _ => false
        }
    }

    pub fn is_reserved(&self) -> bool {
        match self.to_u16(){
            0 | 65535 => true,
            _ => false
        }
    }

}