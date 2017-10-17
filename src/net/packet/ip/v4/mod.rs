

// https://en.wikipedia.org/wiki/IPv4#Packet_structure
#[derive(Debug)]
pub struct Ipv4Packet {
    version: u8,         //  4 bits
    ihl : u8,            //  4 bits
    dscp: u8,            //  6 bits
    ecn: u8,             //  2 bits
    total_length: u16,   // 16 bits
    identification: u16, // 16 bits
    flags: u8,           //  3 bits
    fragment_offset: u16,// 13 bits
    time_to_live: u8,    //  8 bits
    protocol: u8,        //  8 bits
    header_checksum: u16,// 16 bits
    src_ip: u32,         // 32 bits
    dst_ip: u32,         // 32 bits
    options: Option<[u8; 12]>    // 0 - 96 bits, start 160, end 256, if IHL >= 5
}


impl Ipv4Packet {
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