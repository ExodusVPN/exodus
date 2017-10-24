

/// https://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    src_port: u16,
    dst_port: u16,
    length  : u16,
    checksum: u16,
    payload : &'a [u8]
}

impl <'a>Packet<'a> {
    #[allow(unused_variables)]
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!();
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
    
    pub fn src_port(&self) -> u16 {
        self.src_port
    }
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }
    pub fn length(&self) -> u16 {
        self.length
    }
    pub fn checksum(&self) -> u16 {
        self.checksum
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}
