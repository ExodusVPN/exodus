

// https://en.wikipedia.org/wiki/IPv6_packet
#[derive(Debug)]
pub struct Ipv6Packet {
    version: u8,         //  4 bits
    traffic_class: u8,   //  8 bits
    flow_label: u32,     // 20 bits
    payload_length: u16, // 16 bits
    next_header: u8,     //  8 bits
    hoplimit: u8,        //  8 bits
    src_ip  : u128,      // 128 bits
    dst_ip  : u128,      // 128 bits
}

impl Ipv6Packet {
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
