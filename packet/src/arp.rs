
/// Address Resolution Protocol (ARP)
/// 
/// Spec:
/// 
/// *   https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure
/// 
/// *NOTE:*
/// 
///     In Internet Protocol Version 6 (IPv6) networks, 
///     the functionality of ARP is provided by the Neighbor Discovery Protocol (NDP).
/// 
/// Packet size : https://supportforums.cisco.com/t5/lan-switching-and-routing/arp-packet-size/td-p/1551467
#[derive(Debug, PartialEq, Eq)]
pub struct Packet {
    hardware_type: u16,           // 16 bits
    protocol_type: u16,           // 16 bits , EtherType
    hardware_address_length: u8,  //  8 bits
    protocol_address_length: u8,  //  8 bits
    operation: u16,               // 16 bits
    sender_hardware_address: u64, // 48 bits , MacAddr
    sender_protocol_address: u32, // 32 bits , Ipv4Addr
    target_hardware_address: u64, // 48 bits , MacAddr
    target_protocol_address: u32  // 32 bits , Ipv4Addr
}


impl Packet {
    #[allow(unused_variables)]
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!();
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
}


