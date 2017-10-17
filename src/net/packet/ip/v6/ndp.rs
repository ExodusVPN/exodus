

// NDP (Neighbor Discovery Protocol)
// https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol
#[derive(Debug)]
pub struct NDPPacket {

}

impl NDPPacket {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!();
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
}