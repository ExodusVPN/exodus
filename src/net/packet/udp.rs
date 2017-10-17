
// https://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure
#[derive(Debug)]
pub struct UdpPacket {
    src_port: u16,
    dst_port: u16,
    length  : u16,
    checksum: u16,
    data    : Vec<u8>
}

#[derive(Debug)]
pub struct IPv4PseudoHeader{
    src_ip  : u32,
    dst_ip  : u32,
    zeroes  : u8,
    protocol: u8,
    udp_length: u16,

    src_port: u16,
    dst_port: u16,
    length  : u16,
    checksum: u16,
    data    : Vec<u8>
}

#[derive(Debug)]
pub struct IPv6PseudoHeader{
    src_ip     : u128,
    dst_ip     : u128,
    udp_length : u32,
    zeroes     : u32,   // 24 bits
    next_header: u8,
    
    src_port: u16,
    dst_port: u16,
    length  : u16,
    checksum: u16,
    data    : Vec<u8>
}


impl UdpPacket {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!();
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }

    pub fn checksum(&self, ) -> bool {
        // https://en.wikipedia.org/wiki/User_Datagram_Protocol#Checksum_computation
        
    }
}
