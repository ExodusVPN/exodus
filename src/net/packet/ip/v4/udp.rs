

// https://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure
#[derive(Debug)]
pub struct UdpPacket {
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

    pub fn checksum(&self) -> bool {
        unimplemented!();
            
    }
}
