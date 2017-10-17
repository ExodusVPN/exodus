

// https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure
#[derive(Debug)]
pub struct ARPPacket {

}

#[derive(Debug)]
pub struct ARPv6Packet {

}


impl ARPPacket {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!();
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
}

impl ARPv6Packet {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!();
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
}
